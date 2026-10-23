use anyhow::{bail, Context, Result};
use std::ffi::OsString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const BEGIN: &str = "# BEGIN decoupling-loginctl";
const END: &str = "# END decoupling-loginctl";
pub const MANAGED_BLOCK: &str = concat!(
    "# BEGIN decoupling-loginctl\n",
    "-session    optional    pam_sessiond.so timeout=30s\n",
    "-session    optional    pam_aclad.so timeout=30s\n",
    "# END decoupling-loginctl\n",
);
const SESSIOND_MODULE: &str = "/usr/lib/security/pam_sessiond.so";
const ACLAD_MODULE: &str = "/usr/lib/security/pam_aclad.so";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockState {
    Inactive,
    Active,
    Moved,
    Malformed,
}

impl BlockState {
    fn label(self) -> &'static str {
        match self {
            Self::Inactive => "inactive",
            Self::Active => "active",
            Self::Moved => "moved",
            Self::Malformed => "malformed",
        }
    }
}

#[derive(Debug)]
pub struct Status {
    pub target: PathBuf,
    pub state: BlockState,
    pub sessiond_entries: usize,
    pub aclad_entries: usize,
    pub env_anchors: usize,
    pub modules_before_env: bool,
    pub sessiond_module_exists: bool,
    pub aclad_module_exists: bool,
    detail: Option<String>,
}

impl Status {
    pub fn render(&self) -> String {
        let ordering = if self.env_anchors != 1 {
            "ambiguous"
        } else if self.modules_before_env {
            "before pam_env"
        } else {
            "not before pam_env"
        };
        let mut output = format!(
            concat!(
                "PAM file: {}\n",
                "Managed block: {}\n",
                "pam_sessiond.so entries: {}\n",
                "pam_aclad.so entries: {}\n",
                "session pam_env.so anchors: {}\n",
                "Module ordering: {}\n",
                "{}: {}\n",
                "{}: {}\n"
            ),
            self.target.display(),
            self.state.label(),
            self.sessiond_entries,
            self.aclad_entries,
            self.env_anchors,
            ordering,
            SESSIOND_MODULE,
            exists_label(self.sessiond_module_exists),
            ACLAD_MODULE,
            exists_label(self.aclad_module_exists),
        );
        if let Some(detail) = &self.detail {
            output.push_str("Detail: ");
            output.push_str(detail);
            output.push('\n');
        }
        output
    }
}

#[derive(Debug)]
struct Analysis {
    state: BlockState,
    block_range: Option<(usize, usize)>,
    anchors: Vec<(usize, usize)>,
    sessiond_entries: Vec<usize>,
    aclad_entries: Vec<usize>,
    detail: Option<String>,
}

pub fn status(path: &Path) -> Result<Status> {
    status_from(path, Path::new(SESSIOND_MODULE), Path::new(ACLAD_MODULE))
}

pub fn activate(path: &Path) -> Result<String> {
    ensure_root()?;
    activate_impl(path)
}

pub fn deactivate(path: &Path) -> Result<String> {
    ensure_root()?;
    deactivate_impl(path)
}

fn status_from(path: &Path, sessiond_module: &Path, aclad_module: &Path) -> Result<Status> {
    let (contents, _) = read_target(path)?;
    let analysis = analyze(&contents);
    let env_start = analysis.anchors.first().map(|anchor| anchor.0);
    let modules_before_env = env_start.is_some_and(|anchor| {
        !analysis.sessiond_entries.is_empty()
            && !analysis.aclad_entries.is_empty()
            && analysis
                .sessiond_entries
                .iter()
                .chain(&analysis.aclad_entries)
                .all(|offset| *offset < anchor)
    });
    Ok(Status {
        target: path.to_owned(),
        state: analysis.state,
        sessiond_entries: analysis.sessiond_entries.len(),
        aclad_entries: analysis.aclad_entries.len(),
        env_anchors: analysis.anchors.len(),
        modules_before_env,
        sessiond_module_exists: sessiond_module.is_file(),
        aclad_module_exists: aclad_module.is_file(),
        detail: analysis.detail,
    })
}

fn activate_impl(path: &Path) -> Result<String> {
    let _lock = Lock::acquire(path, libc::LOCK_EX)?;
    let (contents, metadata) = read_target(path)?;
    let analysis = analyze(&contents);
    match analysis.state {
        BlockState::Malformed => bail!(
            "refusing to activate: {}",
            analysis
                .detail
                .as_deref()
                .unwrap_or("malformed managed block")
        ),
        BlockState::Moved => {
            bail!("refusing to activate: the exact managed block is not immediately before pam_env")
        }
        BlockState::Active => {
            if analysis.anchors.len() != 1 {
                bail!(
                    "refusing to activate: expected one session pam_env.so anchor, found {}",
                    analysis.anchors.len()
                );
            }
            return Ok(format!(
                "PAM integration is already active in {}.\n",
                path.display()
            ));
        }
        BlockState::Inactive => {}
    }
    if analysis.anchors.len() != 1 {
        bail!(
            "refusing to activate: expected one session pam_env.so anchor, found {}",
            analysis.anchors.len()
        );
    }
    let anchor = analysis.anchors[0].0;
    let mut updated = String::with_capacity(contents.len() + MANAGED_BLOCK.len());
    updated.push_str(&contents[..anchor]);
    updated.push_str(MANAGED_BLOCK);
    updated.push_str(&contents[anchor..]);
    let backup = backup(path, contents.as_bytes(), &metadata)?;
    atomic_replace(path, updated.as_bytes(), &metadata)?;
    Ok(format!(
        "Activated PAM integration in {}.\nBackup: {}\n",
        path.display(),
        backup.display()
    ))
}

fn deactivate_impl(path: &Path) -> Result<String> {
    let _lock = Lock::acquire(path, libc::LOCK_EX)?;
    let (contents, metadata) = read_target(path)?;
    let analysis = analyze(&contents);
    match analysis.state {
        BlockState::Malformed => bail!(
            "refusing to deactivate: {}",
            analysis
                .detail
                .as_deref()
                .unwrap_or("malformed managed block")
        ),
        BlockState::Inactive => {
            return Ok(format!(
                "PAM integration is already inactive in {}.\n",
                path.display()
            ));
        }
        BlockState::Active | BlockState::Moved => {}
    }
    let (start, end) = analysis
        .block_range
        .context("exact managed block range is unavailable")?;
    let mut updated = String::with_capacity(contents.len() - (end - start));
    updated.push_str(&contents[..start]);
    updated.push_str(&contents[end..]);
    let backup = backup(path, contents.as_bytes(), &metadata)?;
    atomic_replace(path, updated.as_bytes(), &metadata)?;
    Ok(format!(
        "Deactivated PAM integration in {}.\nBackup: {}\n",
        path.display(),
        backup.display()
    ))
}

fn analyze(contents: &str) -> Analysis {
    let mut anchors = Vec::new();
    let mut sessiond_entries = Vec::new();
    let mut aclad_entries = Vec::new();
    let mut exact_markers = 0;
    let mut marker_like = 0;
    let mut offset = 0;
    for line in contents.split_inclusive('\n') {
        let text = line.strip_suffix('\n').unwrap_or(line);
        if text.contains("decoupling-loginctl") {
            marker_like += 1;
        }
        if text == BEGIN || text == END {
            exact_markers += 1;
        }
        if let Some(module) = session_module(text) {
            match module {
                "pam_env.so" => anchors.push((offset, offset + line.len())),
                "pam_sessiond.so" => sessiond_entries.push(offset),
                "pam_aclad.so" => aclad_entries.push(offset),
                _ => {}
            }
        }
        offset += line.len();
    }

    let blocks = contents
        .match_indices(MANAGED_BLOCK)
        .map(|(start, block)| (start, start + block.len()))
        .collect::<Vec<_>>();
    if marker_like == 0 {
        return Analysis {
            state: BlockState::Inactive,
            block_range: None,
            anchors,
            sessiond_entries,
            aclad_entries,
            detail: None,
        };
    }
    if blocks.len() != 1 || marker_like != 2 || exact_markers != 2 {
        let detail = if blocks.len() > 1 || exact_markers > 2 {
            "duplicate managed blocks or markers"
        } else {
            "partially edited or malformed managed block"
        };
        return Analysis {
            state: BlockState::Malformed,
            block_range: None,
            anchors,
            sessiond_entries,
            aclad_entries,
            detail: Some(detail.to_owned()),
        };
    }

    let block_range = blocks[0];
    let correctly_placed = anchors.len() == 1 && block_range.1 == anchors[0].0;
    Analysis {
        state: if correctly_placed {
            BlockState::Active
        } else {
            BlockState::Moved
        },
        block_range: Some(block_range),
        anchors,
        sessiond_entries,
        aclad_entries,
        detail: (!correctly_placed).then(|| {
            "exact managed block is not immediately before the sole pam_env anchor".into()
        }),
    }
}

fn session_module(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let fields = trimmed.split_whitespace().collect::<Vec<_>>();
    let service_type = fields.first()?.strip_prefix('-').unwrap_or(fields[0]);
    if service_type != "session" || fields.len() < 3 {
        return None;
    }
    let mut module_index = 2;
    if fields[1].starts_with('[') {
        module_index = fields[1..].iter().position(|field| field.ends_with(']'))? + 2;
    }
    let module = *fields.get(module_index)?;
    Some(module.rsplit('/').next().unwrap_or(module))
}

fn read_target(path: &Path) -> Result<(String, Metadata)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open PAM file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect PAM file {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("PAM target {} is not a regular file", path.display());
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .with_context(|| format!("read PAM file {} as UTF-8", path.display()))?;
    Ok((contents, metadata))
}

struct Lock {
    file: File,
}

impl Lock {
    fn acquire(target: &Path, operation: libc::c_int) -> Result<Self> {
        let parent = target
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .context("PAM target must have a parent directory")?;
        let file_name = target.file_name().context("PAM target has no file name")?;
        let mut lock_name = OsString::from(".");
        lock_name.push(file_name);
        lock_name.push(".loginctl.lock");
        let path = parent.join(lock_name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .with_context(|| format!("open lock {}", path.display()))?;
        // SAFETY: flock only reads the valid file descriptor and operation value.
        if unsafe { libc::flock(file.as_raw_fd(), operation) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("lock {}", path.display()));
        }
        Ok(Self { file })
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        // SAFETY: the descriptor remains valid until the File is dropped.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn backup(path: &Path, contents: &[u8], metadata: &Metadata) -> Result<PathBuf> {
    let parent = path
        .parent()
        .context("PAM target has no parent directory")?;
    let file_name = path.file_name().context("PAM target has no file name")?;
    for attempt in 0..100_u32 {
        let mut name = file_name.to_os_string();
        name.push(format!(".loginctl-backup-{}-{attempt}", timestamp()?));
        let backup = parent.join(name);
        match create_preserved(&backup, contents, metadata) {
            Ok(()) => {
                sync_directory(parent)?;
                return Ok(backup);
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists) => {}
            Err(error) => return Err(error).context("create PAM backup"),
        }
    }
    bail!("could not allocate a unique PAM backup name")
}

fn atomic_replace(path: &Path, contents: &[u8], metadata: &Metadata) -> Result<()> {
    let parent = path
        .parent()
        .context("PAM target has no parent directory")?;
    let file_name = path.file_name().context("PAM target has no file name")?;
    let mut temporary = None;
    for attempt in 0..100_u32 {
        let mut name = OsString::from(".");
        name.push(file_name);
        name.push(format!(".loginctl-tmp-{}-{attempt}", timestamp()?));
        let candidate = parent.join(name);
        match create_preserved(&candidate, contents, metadata) {
            Ok(()) => {
                temporary = Some(candidate);
                break;
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists) => {}
            Err(error) => return Err(error).context("create replacement PAM file"),
        }
    }
    let temporary = temporary.context("could not allocate a unique temporary PAM file")?;
    if let Err(error) = std::fs::rename(&temporary, path)
        .with_context(|| format!("atomically replace {}", path.display()))
        .and_then(|()| sync_directory(parent))
    {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

fn create_preserved(path: &Path, contents: &[u8], metadata: &Metadata) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(metadata.mode() & 0o7777)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    if let Err(error) = (|| -> Result<()> {
        file.write_all(contents)?;
        // SAFETY: fchown acts on a valid descriptor and uses saved numeric IDs.
        if unsafe { libc::fchown(file.as_raw_fd(), metadata.uid(), metadata.gid()) } != 0 {
            return Err(std::io::Error::last_os_error()).context("preserve owner and group");
        }
        file.set_permissions(std::fs::Permissions::from_mode(metadata.mode() & 0o7777))?;
        file.sync_all()?;
        Ok(())
    })() {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("open directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("sync directory {}", path.display()))
}

fn timestamp() -> Result<String> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?;
    Ok(format!(
        "{}-{:09}",
        elapsed.as_secs(),
        elapsed.subsec_nanos()
    ))
}

fn ensure_root() -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("PAM mutation requires an already-root caller");
    }
    Ok(())
}

fn exists_label(exists: bool) -> &'static str {
    if exists {
        "present"
    } else {
        "missing"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use tempfile::TempDir;

    const BASE: &str = concat!(
        "auth required pam_unix.so\n",
        "session required pam_unix.so\n",
        "session required pam_env.so\n",
    );

    fn fixture(contents: &str) -> (TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("system-login");
        std::fs::write(&path, contents).expect("write fixture");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("set fixture mode");
        (directory, path)
    }

    fn activate_fixture(path: &Path) -> Result<String> {
        activate_impl(path)
    }

    fn deactivate_fixture(path: &Path) -> Result<String> {
        deactivate_impl(path)
    }

    #[test]
    fn classifies_inactive_active_moved_malformed_and_duplicate_blocks() {
        assert_eq!(analyze(BASE).state, BlockState::Inactive);
        let active = BASE.replace(
            "session required pam_env.so\n",
            &format!("{MANAGED_BLOCK}session required pam_env.so\n"),
        );
        assert_eq!(analyze(&active).state, BlockState::Active);
        assert_eq!(
            analyze(&format!("{MANAGED_BLOCK}{BASE}")).state,
            BlockState::Moved
        );
        assert_eq!(
            analyze(&active.replace("timeout=30s", "timeout=5s")).state,
            BlockState::Malformed
        );
        assert_eq!(
            analyze(&format!("{MANAGED_BLOCK}{MANAGED_BLOCK}{BASE}")).state,
            BlockState::Malformed
        );
    }

    #[test]
    fn activation_is_atomic_idempotent_and_preserves_metadata() {
        let (directory, path) = fixture(BASE);
        let before = std::fs::metadata(&path).expect("metadata");
        let first = activate_fixture(&path).expect("activate");
        assert!(first.contains("Backup:"));
        let expected = BASE.replace(
            "session required pam_env.so\n",
            &format!("{MANAGED_BLOCK}session required pam_env.so\n"),
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), expected);
        let after = std::fs::metadata(&path).expect("metadata");
        assert_eq!(before.uid(), after.uid());
        assert_eq!(before.gid(), after.gid());
        assert_eq!(before.mode() & 0o7777, after.mode() & 0o7777);
        assert_eq!(backup_count(&directory), 1);

        let second = activate_fixture(&path).expect("idempotent activate");
        assert!(second.contains("already active"));
        assert_eq!(backup_count(&directory), 1);
        assert!(!directory.path().read_dir().unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("tmp")));
    }

    #[test]
    fn deactivation_removes_only_the_exact_block_and_is_idempotent() {
        let admin_line = "session optional pam_sessiond.so timeout=10s\n";
        let active = BASE.replace(
            "session required pam_env.so\n",
            &format!("{admin_line}{MANAGED_BLOCK}session required pam_env.so\n"),
        );
        let (directory, path) = fixture(&active);
        deactivate_fixture(&path).expect("deactivate");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            BASE.replace(
                "session required pam_env.so\n",
                &format!("{admin_line}session required pam_env.so\n")
            )
        );
        assert_eq!(backup_count(&directory), 1);
        assert!(deactivate_fixture(&path)
            .expect("idempotent deactivate")
            .contains("already inactive"));
        assert_eq!(backup_count(&directory), 1);
    }

    #[test]
    fn mutation_rejects_ambiguous_anchors_and_bad_blocks() {
        let (_directory, zero) = fixture("session required pam_unix.so\n");
        assert!(activate_fixture(&zero)
            .unwrap_err()
            .to_string()
            .contains("found 0"));
        let (_directory, two) = fixture(concat!(
            "session required pam_env.so\n",
            "session optional pam_env.so\n"
        ));
        assert!(activate_fixture(&two)
            .unwrap_err()
            .to_string()
            .contains("found 2"));
        let malformed = BASE.replace(
            "session required pam_env.so\n",
            concat!(
                "# BEGIN decoupling-loginctl\n",
                "-session optional pam_sessiond.so\n",
                "# END decoupling-loginctl\n",
                "session required pam_env.so\n"
            ),
        );
        let (_directory, malformed) = fixture(&malformed);
        assert!(activate_fixture(&malformed).is_err());
        assert!(deactivate_fixture(&malformed).is_err());
    }

    #[test]
    fn status_reports_presence_ordering_module_files_and_malformed_detail() {
        let active = BASE.replace(
            "session required pam_env.so\n",
            &format!("{MANAGED_BLOCK}session required pam_env.so\n"),
        );
        let (directory, path) = fixture(&active);
        let sessiond = directory.path().join("pam_sessiond.so");
        std::fs::write(&sessiond, "").unwrap();
        let status = status_from(&path, &sessiond, &directory.path().join("missing.so")).unwrap();
        assert_eq!(status.state, BlockState::Active);
        assert_eq!(status.sessiond_entries, 1);
        assert_eq!(status.aclad_entries, 1);
        assert_eq!(status.env_anchors, 1);
        assert!(status.modules_before_env);
        assert!(status.sessiond_module_exists);
        assert!(!status.aclad_module_exists);
        let rendered = status.render();
        assert!(rendered.contains("Managed block: active"));
        assert!(rendered.contains("Module ordering: before pam_env"));
    }

    #[test]
    fn recognizes_bracketed_control_and_absolute_module_paths() {
        assert_eq!(
            session_module("-session [success=1 default=ignore] /usr/lib/security/pam_env.so"),
            Some("pam_env.so")
        );
        assert_eq!(session_module("auth required pam_env.so"), None);
        assert_eq!(session_module("# session required pam_env.so"), None);
    }

    fn backup_count(directory: &TempDir) -> usize {
        directory
            .path()
            .read_dir()
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains("loginctl-backup")
            })
            .count()
    }
}
