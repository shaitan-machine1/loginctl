use lib_sessiond::SessionInfo;

pub struct SessionRow {
    pub session: SessionInfo,
    pub master: Option<(u32, u64)>,
}
use libmultiseatd::ContextInfo;
use seat_udev::{SeatDevice, SeatName};
use std::fmt::Write;
use std::path::PathBuf;

/// Preserve remote categories in human diagnostics as well as typed errors.
pub fn failure(error: &anyhow::Error) -> String {
    let mut text = format!("{error:#}");
    if let Some(remote) = error.downcast_ref::<dbus::Error>() {
        if let Some(name) = remote.name() {
            write!(text, " [{name}]").expect("String write");
        }
    }
    if let Some(session) = error.downcast_ref::<lib_sessiond::Error>() {
        write!(text, " [sessiond {:?}", session.code).expect("String write");
        if let Some(name) = &session.remote_name {
            write!(text, ": {name}").expect("String write");
        }
        text.push(']');
    }
    if let Some(refresh) = error.downcast_ref::<libmultiseatd::RefreshError>() {
        for failure in &refresh.failures {
            if let Some(name) = failure.error.name() {
                write!(text, " [{} {:?}: {name}]", failure.seat, failure.stage)
                    .expect("String write");
            }
        }
    }
    text
}
pub fn seats(seats: &[String]) -> String {
    if seats.is_empty() {
        return "No seats.\n".into();
    }
    let mut output = "CONFIGURED SEAT\n".to_owned();
    for name in seats {
        writeln!(output, "{name}").expect("String write");
    }
    output
}

pub fn sessions(sessions: &[SessionRow]) -> String {
    if sessions.is_empty() {
        return "No sessions.\n".to_owned();
    }
    let session_width = sessions
        .iter()
        .map(|row| row.session.sid.len())
        .chain(["SESSION".len()])
        .max()
        .expect("heading provides a width");
    let uid_width = sessions
        .iter()
        .map(|row| row.session.uid.to_string().len())
        .chain(["UID".len()])
        .max()
        .expect("heading provides a width");
    let runtime_width = sessions
        .iter()
        .map(|row| row.session.runtime_dir.len())
        .chain(["RUNTIME_DIR".len()])
        .max()
        .expect("heading width");
    let mut output = String::new();
    writeln!(
        output,
        "{:<session_width$}  {:>uid_width$}  {:<runtime_width$}  MASTER  START",
        "SESSION", "UID", "RUNTIME_DIR"
    )
    .expect("String write");
    for row in sessions {
        let (master, start) = row
            .master
            .map_or(("-".to_owned(), "-".to_owned()), |(pid, start)| {
                (pid.to_string(), start.to_string())
            });
        writeln!(
            output,
            "{:<session_width$}  {:>uid_width$}  {:<runtime_width$}  {master}  {start}",
            row.session.sid, row.session.uid, row.session.runtime_dir
        )
        .expect("String write");
    }
    output
}

pub fn scopes(scopes: &[String]) -> String {
    if scopes.is_empty() {
        return "No matching scopes.\n".to_owned();
    }
    let mut output = "SCOPE\n".to_owned();
    for scope in scopes {
        writeln!(output, "{scope}").expect("writing to String cannot fail");
    }
    output
}

pub fn scope_of(pid: u32, scope: &str) -> String {
    if scope.is_empty() {
        return format!("PID {pid} is not in a managed scope.\n");
    }
    let pid_width = pid.to_string().len().max("PID".len());
    format!("{:>pid_width$}  SCOPE\n{pid:>pid_width$}  {scope}\n", "PID")
}

pub fn contexts(contexts: &[ContextInfo]) -> String {
    if contexts.is_empty() {
        return "No contexts.\n".into();
    }
    let mut output = "CONTEXT  VT  UIDS  ACTIVE  FOREGROUND  EFFECTIVE  CONNECTIONS\n".to_owned();
    for context in contexts {
        let users = context
            .desired_uids
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        writeln!(
            output,
            "{}  {}  {users}  {}  {}  {}  {}",
            context.id,
            context.vt,
            context.active,
            context.foreground,
            context.effective,
            context
                .connection_handles
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
        .expect("String write");
    }
    output
}

pub fn seat_topology(seat: &SeatName, devices: &[SeatDevice], static_nodes: &[PathBuf]) -> String {
    let mut output = format!("  {seat}\n    udev topology:\n");
    for device in devices {
        writeln!(
            output,
            "      {}{}{}",
            device
                .devnode
                .as_deref()
                .unwrap_or(&device.syspath)
                .display(),
            if device.master_of_seat {
                " [master]"
            } else {
                ""
            },
            if device.uaccess { " [uaccess]" } else { "" }
        )
        .expect("String write");
    }
    output.push_str("    brokered devices:\n");
    for device in devices.iter().filter(|device| device.brokerable()) {
        writeln!(
            output,
            "      {}",
            device.devnode.as_ref().unwrap().display()
        )
        .expect("String write");
    }
    output.push_str("    direct-access devices:\n");
    for device in devices.iter().filter(|device| device.direct_access()) {
        writeln!(
            output,
            "      {}",
            device.devnode.as_ref().unwrap().display()
        )
        .expect("String write");
    }
    output.push_str("    static direct-access nodes:\n");
    for path in static_nodes {
        writeln!(output, "      {}", path.display()).expect("String write");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0123456789abcdef0123456789abcdef";
    const B: &str = "1123456789abcdef0123456789abcdef";

    #[test]
    fn critical_remote_categories_survive_human_diagnostics() {
        let error = anyhow::Error::new(
            libmultiseatd::ErrorKind::CriticalFailure.error("ACL deadline expired"),
        );
        assert!(failure(&error).contains("org.SGLogin.Multiseatd1.Error.CriticalFailure"));
        let error = anyhow::Error::new(libmultiseatd::RefreshError {
            addition_started: false,
            failures: vec![libmultiseatd::SeatFailure {
                seat: "seat0".into(),
                stage: libmultiseatd::RefreshStage::Removal,
                error: libmultiseatd::ErrorKind::CriticalFailure.error("ACL deadline expired"),
            }],
        });
        assert!(failure(&error)
            .contains("seat0 Removal: org.SGLogin.Multiseatd1.Error.CriticalFailure"));
    }
    #[test]
    fn session_errors_keep_typed_and_remote_categories() {
        let error = anyhow::Error::new(lib_sessiond::Error {
            code: lib_sessiond::ErrorCode::Pending,
            message: "removal pending".into(),
            remote_name: Some("org.SGLogin.Sessiond1.Error.Pending".into()),
        });
        assert!(failure(&error).contains("[sessiond Pending: org.SGLogin.Sessiond1.Error.Pending]"));
    }

    #[test]
    fn renders_explicit_empty_states() {
        assert_eq!(seats(&[]), "No seats.\n");
        assert_eq!(sessions(&[]), "No sessions.\n");
        assert_eq!(scopes(&[]), "No matching scopes.\n");
        assert_eq!(contexts(&[]), "No contexts.\n");
    }

    #[test]
    fn renders_aligned_session_table_without_reordering() {
        let text = sessions(&[
            SessionRow {
                session: SessionInfo {
                    sid: B.into(),
                    uid: 7,
                    runtime_dir: "/run/user/7".into(),
                },
                master: None,
            },
            SessionRow {
                session: SessionInfo {
                    sid: A.into(),
                    uid: 1000,
                    runtime_dir: "/run/user/1000".into(),
                },
                master: Some((42, 99)),
            },
        ]);
        let columns: Vec<Vec<&str>> = text
            .lines()
            .map(|line| line.split_whitespace().collect())
            .collect();
        assert_eq!(
            columns,
            [
                vec!["SESSION", "UID", "RUNTIME_DIR", "MASTER", "START"],
                vec![B, "7", "/run/user/7", "-", "-"],
                vec![A, "1000", "/run/user/1000", "42", "99"]
            ]
        );
    }

    #[test]
    fn renders_scope_lookup_and_seven_context_fields() {
        assert_eq!(scope_of(99, ""), "PID 99 is not in a managed scope.\n");
        let id = "01900000-0000-7000-8000-000000000000".parse().unwrap();
        let text = contexts(&[ContextInfo {
            id,
            vt: 7,
            desired_uids: vec![1000],
            connection_handles: vec![1, 2],
            active: true,
            foreground: true,
            effective: true,
        }]);
        assert!(text.contains("7  1000  true  true  true  1,2"));
        assert!(!text.contains("CLEANUP"));
        assert!(!text.contains("PHASE"));
    }

    #[test]
    fn topology_separates_brokered_direct_and_static_nodes() {
        let seat = SeatName::seat0();
        let mut direct = SeatDevice {
            syspath: "/sys/audio".into(),
            devnode: Some("/dev/audio".into()),
            devnum: None,
            node_identity: None,
            seat: seat.clone(),
            kind: seat_udev::DeviceKind::Other,
            uaccess: true,
            master_of_seat: false,
        };
        let mut brokered = direct.clone();
        brokered.kind = seat_udev::DeviceKind::Evdev;
        brokered.devnode = Some("/dev/input/event0".into());
        direct.master_of_seat = true;
        let rendered = seat_topology(&seat, &[direct, brokered], &["/dev/static".into()]);
        assert!(rendered.contains("brokered devices:\n      /dev/input/event0\n    direct-access devices:\n      /dev/audio\n"));
        assert!(rendered.contains("static direct-access nodes:\n      /dev/static"));
        assert!(rendered.contains("udev topology:"));
    }
}
