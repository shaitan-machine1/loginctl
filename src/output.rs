use lib_sessiond::Session;
use libmultiseatd::ContextInfo;
use seat_udev::{SeatDevice, SeatName};
use std::fmt::Write;
use std::path::PathBuf;

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

pub fn sessions(sessions: &[Session]) -> String {
    if sessions.is_empty() {
        return "No sessions.\n".to_owned();
    }
    let session_width = sessions
        .iter()
        .map(|session| session.id.len())
        .chain(["SESSION".len()])
        .max()
        .expect("heading provides a width");
    let uid_width = sessions
        .iter()
        .map(|session| session.uid.to_string().len())
        .chain(["UID".len()])
        .max()
        .expect("heading provides a width");
    let mut output = String::new();
    writeln!(
        output,
        "{:<session_width$}  {:>uid_width$}  LEADER  START",
        "SESSION", "UID"
    )
    .expect("writing to String cannot fail");
    for session in sessions {
        let (leader, start) = session
            .leader
            .map_or(("-".to_owned(), "-".to_owned()), |identity| {
                (identity.pid.to_string(), identity.start_time.to_string())
            });
        writeln!(
            output,
            "{:<session_width$}  {:>uid_width$}  {leader}  {start}",
            session.id, session.uid
        )
        .expect("writing to String cannot fail");
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
    fn renders_explicit_empty_states() {
        assert_eq!(seats(&[]), "No seats.\n");
        assert_eq!(sessions(&[]), "No sessions.\n");
        assert_eq!(scopes(&[]), "No matching scopes.\n");
        assert_eq!(contexts(&[]), "No contexts.\n");
    }

    #[test]
    fn renders_aligned_session_table_without_reordering() {
        assert_eq!(
            sessions(&[
                Session {
                    id: B.to_owned(),
                    uid: 7,
                    leader: None
                },
                Session {
                    id: A.to_owned(),
                    uid: 1000,
                    leader: Some(lib_scoped::ProcessIdentity {
                        pid: 42,
                        start_time: 99
                    })
                },
            ]),
            concat!(
                "SESSION                            UID  LEADER  START\n",
                "1123456789abcdef0123456789abcdef     7  -  -\n",
                "0123456789abcdef0123456789abcdef  1000  42  99\n",
            )
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
