use lib_sessiond::Session;
use libmultiseatd::ClientRow;
use seat_udev::{SeatDevice, SeatName};
use std::fmt::Write;
use std::path::PathBuf;

pub fn seats(seats: &[String]) -> String {
    if seats.is_empty() {
        return "No seats.\n".to_owned();
    }
    let mut output = "SEAT\n".to_owned();
    for seat in seats {
        writeln!(output, "{seat}").expect("writing to String cannot fail");
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

pub fn clients(clients: &[ClientRow]) -> String {
    if clients.is_empty() {
        return "No seat clients.\n".into();
    }
    let mut output = "CLIENT  SEAT  UID  STATE\n".to_owned();
    for (id, seat, uid, state) in clients {
        writeln!(output, "{id}  {seat}  {uid}  {state}").expect("String write");
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
        assert_eq!(clients(&[]), "No seat clients.\n");
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
    fn renders_scope_lookup_and_clients_without_process_kill_language() {
        assert_eq!(scope_of(99, ""), "PID 99 is not in a managed scope.\n");
        assert_eq!(
            clients(&[(
                "opaque-id".into(),
                "seat0".into(),
                1000,
                "pending-disable".into()
            )]),
            "CLIENT  SEAT  UID  STATE\nopaque-id  seat0  1000  pending-disable\n"
        );
    }

    #[test]
    fn topology_separates_brokered_direct_and_static_nodes() {
        let seat = SeatName::seat0();
        let mut direct = SeatDevice {
            syspath: "/sys/audio".into(),
            devnode: Some("/dev/audio".into()),
            devnum: None,
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
