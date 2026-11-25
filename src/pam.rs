use anyhow::{bail, Context, Result};
use std::ffi::OsString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
const BEGIN: &str = "# BEGIN sglogin";
const END: &str = "# END sglogin";
pub const MANAGED_BLOCK: &str =
    "# BEGIN sglogin\nsession include sessiond-session\n# END sglogin\n";
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockState {
    Inactive,
    Active,
    Malformed,
}
impl BlockState {
    fn label(self) -> &'static str {
        match self {
            Self::Inactive => "inactive",
            Self::Active => "active",
            Self::Malformed => "malformed",
        }
    }
}
#[derive(Debug)]
pub struct Status {
    pub target: PathBuf,
    pub state: BlockState,
    pub canonical: bool,
    pub env_anchors: usize,
    pub before_env: bool,
    detail: Option<String>,
}
impl Status {
    pub fn render(&self) -> String {
        let mut output = format!("PAM file: {}\nManaged block: {}\nCanonical include: {}\nSession pam_env.so anchors: {}\nBlock before pam_env: {}\n", self.target.display(), self.state.label(), self.canonical, self.env_anchors, self.before_env);
        if let Some(detail) = &self.detail {
            output.push_str(&format!("Detail: {detail}\n"));
        }
        output
    }
}
struct Analysis {
    state: BlockState,
    range: Option<(usize, usize)>,
    anchors: Vec<usize>,
    detail: Option<String>,
}
pub fn status(path: &Path) -> Result<Status> {
    let (contents, _) = read_target(path)?;
    let analysis = analyze(&contents);
    Ok(Status {
        target: path.into(),
        state: analysis.state,
        canonical: analysis
            .range
            .is_some_and(|(a, b)| &contents[a..b] == MANAGED_BLOCK),
        env_anchors: analysis.anchors.len(),
        before_env: analysis.range.is_some_and(|(_, end)| {
            analysis
                .anchors
                .first()
                .is_some_and(|anchor| end <= *anchor)
        }),
        detail: analysis.detail,
    })
}
pub fn activate(path: &Path) -> Result<String> {
    ensure_root()?;
    change(path, true)
}
pub fn deactivate(path: &Path) -> Result<String> {
    ensure_root()?;
    change(path, false)
}
fn change(path: &Path, activate: bool) -> Result<String> {
    let _lock = Lock::acquire(path)?;
    let (contents, metadata) = read_target(path)?;
    let analysis = analyze(&contents);
    if analysis.state == BlockState::Malformed {
        bail!(
            "refusing PAM edit: {}",
            analysis.detail.as_deref().unwrap_or("ambiguous markers")
        );
    }
    let (start, end) = match analysis.range {
        Some(range) => range,
        None if !activate => {
            return Ok(format!(
                "PAM integration is already inactive in {}.\n",
                path.display()
            ))
        }
        None => {
            if analysis.anchors.len() != 1 {
                bail!(
                    "refusing to activate: expected one session pam_env.so anchor, found {}",
                    analysis.anchors.len()
                );
            }
            (analysis.anchors[0], analysis.anchors[0])
        }
    };
    let replacement = if activate { MANAGED_BLOCK } else { "" };
    if &contents[start..end] == replacement {
        return Ok(format!(
            "PAM integration is already active in {}.\n",
            path.display()
        ));
    }
    let updated = format!("{}{replacement}{}", &contents[..start], &contents[end..]);
    let saved = backup(path, contents.as_bytes(), &metadata)?;
    atomic_replace(path, updated.as_bytes(), &metadata)?;
    Ok(format!(
        "{} PAM integration in {}.\nBackup: {}\n",
        if activate { "Updated" } else { "Deactivated" },
        path.display(),
        saved.display()
    ))
}
fn analyze(contents: &str) -> Analysis {
    let mut markers = Vec::new();
    let mut anchors = Vec::new();
    let mut offset = 0;
    let mut ambiguous = false;
    for line in contents.split_inclusive('\n') {
        let text = line.strip_suffix('\n').unwrap_or(line);
        if text == BEGIN || text == END {
            markers.push((text == BEGIN, offset, offset + line.len()));
        } else if text.trim_start().starts_with(BEGIN) || text.trim_start().starts_with(END) {
            ambiguous = true;
        }
        if session_module(text) == Some("pam_env.so") {
            anchors.push(offset);
        }
        offset += line.len();
    }
    // Only our two exact markers are recognized. Never inspect an included
    // fragment, module installation, other sessiond entries or old markers.
    let range = match markers.as_slice() {
        [(true, begin, _), (false, _, end)] if !ambiguous => Some((*begin, *end)),
        [] if !ambiguous => {
            return Analysis {
                state: BlockState::Inactive,
                range: None,
                anchors,
                detail: None,
            }
        }
        _ => {
            return Analysis {
                state: BlockState::Malformed,
                range: None,
                anchors,
                detail: Some("unmatched, duplicate, reversed or ambiguous sglogin markers".into()),
            }
        }
    };
    Analysis {
        state: BlockState::Active,
        range,
        anchors,
        detail: None,
    }
}
fn session_module(line: &str) -> Option<&str> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let kind = fields.first()?.strip_prefix('-').unwrap_or(fields[0]);
    if kind != "session" || fields.len() < 3 {
        return None;
    }
    let index = if fields[1].starts_with('[') {
        fields[1..].iter().position(|f| f.ends_with(']'))? + 2
    } else {
        2
    };
    fields.get(index)?.rsplit('/').next()
}
fn read_target(path: &Path) -> Result<(String, Metadata)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open PAM file {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("PAM target is not a regular file");
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok((contents, metadata))
}
// These are administrative configuration-edit locks, not session lifecycle locks.
struct Lock(File);
impl Lock {
    fn acquire(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .context("PAM target has no parent")?;
        let mut name = OsString::from(".");
        name.push(path.file_name().context("PAM target has no file name")?);
        name.push(".loginctl.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(parent.join(name))?;
        // SAFETY: descriptor is live; flock's operation is a constant.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error()).context("lock PAM edit");
        }
        Ok(Self(file))
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        // SAFETY: live owned descriptor.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
fn backup(path: &Path, contents: &[u8], metadata: &Metadata) -> Result<PathBuf> {
    let parent = path.parent().context("PAM target has no parent")?;
    for attempt in 0..100 {
        let mut name = path
            .file_name()
            .context("missing file name")?
            .to_os_string();
        name.push(format!(".loginctl-backup-{}-{attempt}", timestamp()?));
        let candidate = parent.join(name);
        match create_preserved(&candidate, contents, metadata) {
            Ok(()) => {
                sync_directory(parent)?;
                return Ok(candidate);
            }
            Err(error) if exists(&error) => {}
            Err(error) => return Err(error).context("create PAM backup"),
        }
    }
    bail!("cannot allocate PAM backup")
}
fn exists(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::AlreadyExists)
}
fn atomic_replace(path: &Path, contents: &[u8], metadata: &Metadata) -> Result<()> {
    let parent = path.parent().context("PAM target has no parent")?;
    for attempt in 0..100 {
        let mut name = OsString::from(".");
        name.push(path.file_name().context("missing file name")?);
        name.push(format!(".loginctl-tmp-{}-{attempt}", timestamp()?));
        let candidate = parent.join(name);
        match create_preserved(&candidate, contents, metadata) {
            Ok(()) => {
                let result = std::fs::rename(&candidate, path)
                    .context("replace PAM file")
                    .and_then(|()| sync_directory(parent));
                if result.is_err() {
                    let _ = std::fs::remove_file(&candidate);
                }
                return result;
            }
            Err(error) if exists(&error) => {}
            Err(error) => return Err(error).context("create PAM replacement"),
        }
    }
    bail!("cannot allocate PAM replacement")
}
fn create_preserved(path: &Path, contents: &[u8], metadata: &Metadata) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(metadata.mode() & 0o7777)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let result = (|| -> Result<()> {
        file.write_all(contents)?;
        // SAFETY: live descriptor; preserve saved numeric owner and group.
        if unsafe { libc::fchown(file.as_raw_fd(), metadata.uid(), metadata.gid()) } != 0 {
            return Err(std::io::Error::last_os_error()).context("preserve PAM ownership");
        }
        file.set_permissions(std::fs::Permissions::from_mode(metadata.mode() & 0o7777))?;
        file.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
    }
    result
}
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all().context("sync PAM directory")
}
fn timestamp() -> Result<String> {
    let t = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(format!("{}-{:09}", t.as_secs(), t.subsec_nanos()))
}
fn ensure_root() -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("PAM mutation requires an already-root caller");
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    const BASE: &str =
        "auth required pam_unix.so\nsession required pam_unix.so\nsession required pam_env.so\n";
    fn fixture(text: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("system-login");
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        (dir, path)
    }
    fn backup_count(dir: &tempfile::TempDir) -> usize {
        dir.path()
            .read_dir()
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains("loginctl-backup")
            })
            .count()
    }
    #[test]
    fn insertion_is_idempotent_atomic_and_preserves_metadata_and_backup() {
        let (dir, path) = fixture(BASE);
        let before = std::fs::metadata(&path).unwrap();
        change(&path, true).unwrap();
        let expected = BASE.replace(
            "session required pam_env.so\n",
            &format!("{MANAGED_BLOCK}session required pam_env.so\n"),
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), expected);
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(
            (before.uid(), before.gid(), before.mode()),
            (after.uid(), after.gid(), after.mode())
        );
        assert!(change(&path, true).unwrap().contains("already active"));
        assert_eq!(backup_count(&dir), 1);
        assert!(status(&path).unwrap().canonical);
        change(&path, false).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), BASE);
        assert!(change(&path, false).unwrap().contains("already inactive"));
        assert_eq!(backup_count(&dir), 2);
    }
    #[test]
    fn edited_interior_is_replaced_in_place_without_anchor_or_other_entry_validation() {
        let outside = "session optional pam_sessiond_ready.so\n# administrator comment\n";
        let text = format!("{outside}# BEGIN sglogin\nanything\nsession optional nonexistent.so\n# END sglogin\nauth required pam_unix.so\n");
        let (_dir, path) = fixture(&text);
        assert_eq!(status(&path).unwrap().state, BlockState::Active);
        assert!(!status(&path).unwrap().canonical);
        change(&path, true).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{outside}{MANAGED_BLOCK}auth required pam_unix.so\n")
        );
        std::fs::write(&path, &text).unwrap();
        change(&path, false).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{outside}auth required pam_unix.so\n")
        );
    }
    #[test]
    fn a_moved_block_is_not_relocated_and_old_markers_are_not_recognized() {
        let old = "# BEGIN decoupling-loginctl\nold contents\n# END decoupling-loginctl\n";
        let (_dir, path) = fixture(&format!("{old}{MANAGED_BLOCK}{BASE}"));
        change(&path, true).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{old}{MANAGED_BLOCK}{BASE}")
        );
        change(&path, false).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("{old}{BASE}")
        );
        assert_eq!(analyze(old).state, BlockState::Inactive);
    }
    #[test]
    fn malformed_boundaries_and_absent_insertion_anchors_are_rejected_without_changes() {
        for text in [
            "# BEGIN sglogin\n",
            "# END sglogin\n",
            "# END sglogin\n# BEGIN sglogin\n",
            " # BEGIN sglogin\n# END sglogin\n",
            "# BEGIN sglogin edited\n# END sglogin\n",
            "# BEGIN sglogin\n# BEGIN sglogin\n# END sglogin\n",
            "# BEGIN sglogin\n# END sglogin\n# END sglogin\n",
        ] {
            let (_dir, path) = fixture(text);
            assert!(change(&path, true).is_err());
            assert!(change(&path, false).is_err());
            assert_eq!(std::fs::read_to_string(path).unwrap(), text);
        }
        for text in [
            "session required pam_unix.so\n",
            "session required pam_env.so\nsession optional pam_env.so\n",
        ] {
            let (_dir, path) = fixture(text);
            assert!(change(&path, true).is_err());
        }
    }
    #[test]
    fn root_and_symlink_guards_remain_and_bracketed_env_anchor_is_supported() {
        let (dir, path) =
            fixture("-session [success=1 default=ignore] /usr/lib/security/pam_env.so\n");
        change(&path, true).unwrap();
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(status(&link).is_err());
        // SAFETY: read effective UID.
        if unsafe { libc::geteuid() } != 0 {
            assert!(activate(&path)
                .unwrap_err()
                .to_string()
                .contains("already-root"));
        }
        assert_eq!(session_module("# session required pam_env.so"), None);
    }
}
