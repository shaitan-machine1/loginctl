use dbus::blocking::Connection;
use dbus::channel::MatchingReceiver;
use dbus::message::MatchRule;
use dbus_crossroads::Crossroads;
use loginctl::admin;
use loginctl::cli::{ClientCommand, ScopeCommand, SeatCommand, SessionCommand};
const CLIENT_ID: &str = "01900000-0000-7000-8000-000000000000";
use std::os::fd::{AsRawFd, IntoRawFd};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct PrivateBus {
    pid: i32,
    old_address: Option<String>,
}
impl PrivateBus {
    fn start() -> Self {
        let output = Command::new("dbus-daemon")
            .args(["--session", "--fork", "--print-address=1", "--print-pid=1"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        let mut lines = stdout.lines();
        let address = lines.next().unwrap().to_owned();
        let pid = lines.next().unwrap().parse().unwrap();
        let old_address = std::env::var("DBUS_SYSTEM_BUS_ADDRESS").ok();
        // SAFETY: this integration test is one process-wide test and restores
        // the variable after all client/server connections are dropped.
        unsafe { std::env::set_var("DBUS_SYSTEM_BUS_ADDRESS", address) };
        Self { pid, old_address }
    }
}
impl Drop for PrivateBus {
    fn drop(&mut self) {
        unsafe {
            if let Some(address) = &self.old_address {
                std::env::set_var("DBUS_SYSTEM_BUS_ADDRESS", address);
            } else {
                std::env::remove_var("DBUS_SYSTEM_BUS_ADDRESS");
            }
            libc::kill(self.pid, libc::SIGTERM);
        }
    }
}
struct Server {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Server {
    fn start() -> Self {
        let connection = Connection::new_system().unwrap();
        for name in [lib_sessiond::bus::BUS_NAME, libmultiseatd::BUS_NAME] {
            connection.request_name(name, false, false, true).unwrap();
        }
        let mut crossroads = Crossroads::new();
        let session = crossroads.register(lib_sessiond::bus::INTERFACE_NAME, |builder| {
            builder.method(
                "CloseSessionAndWait",
                ("sid",),
                (),
                |_, _, (_sid,): (String,)| Ok(()),
            );
            builder.method("ListSessions", (), ("sessions",), |_, _, ()| {
                Ok((vec![(
                    "0123456789abcdef0123456789abcdef".to_owned(),
                    1000u32,
                )],))
            });
        });
        let seats = crossroads.register(libmultiseatd::INTERFACE_NAME, |builder| {
            builder.method("ListSeats", (), ("seats",), |_, _, ()| {
                Ok((vec!["seat0".to_owned()],))
            });
            builder.method(
                "CreateClient",
                ("seat", "uid"),
                ("client_id", "fd"),
                |_, _, (seat, uid): (String, u32)| {
                    assert_eq!((seat.as_str(), uid), ("seat0", 1000));
                    let (fd, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
                    // SAFETY: transfer the descriptor to the D-Bus value once.
                    let fd = unsafe { dbus::arg::OwnedFd::new(fd.into_raw_fd()) };
                    Ok((CLIENT_ID.to_owned(), fd))
                },
            );
            builder.method(
                "RevokeClient",
                ("client_id",),
                (),
                |_, _, (id,): (String,)| {
                    assert_eq!(id, CLIENT_ID);
                    Ok(())
                },
            );
            builder.method("ListClients", (), ("clients",), |_, _, ()| {
                Ok((vec![
                    (
                        CLIENT_ID.to_owned(),
                        "seat0".to_owned(),
                        1000u32,
                        "active".to_owned(),
                    ),
                    (
                        "01900000-0000-7000-8000-000000000001".to_owned(),
                        "seat1".to_owned(),
                        1001u32,
                        "connected".to_owned(),
                    ),
                ],))
            });
        });
        crossroads.insert(lib_sessiond::bus::OBJECT_PATH, &[session], ());
        crossroads.insert(libmultiseatd::OBJECT_PATH, &[seats], ());
        connection.start_receive(
            MatchRule::new_method_call(),
            Box::new(move |message, connection| {
                crossroads.handle_message(message, connection).unwrap();
                true
            }),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread = std::thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                connection.process(Duration::from_millis(20)).unwrap();
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

#[test]
fn commands_use_synchronous_component_clients_and_direct_scopes() {
    let _bus = PrivateBus::start();
    let server = Server::start();
    assert_eq!(admin::seat(SeatCommand::List, 15).unwrap(), "SEAT\nseat0\n");
    let client = libmultiseatd::Client::system(Duration::from_secs(2)).unwrap();
    let (id, fd) = client.create_client("seat0", 1000).unwrap();
    assert_eq!(id, CLIENT_ID);
    // SAFETY: fd is live for the duration of this fcntl call.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    assert_ne!(flags & libc::FD_CLOEXEC, 0);
    drop(fd);
    client.revoke_client(&id).unwrap();
    let all = admin::seat(
        SeatCommand::Client {
            command: ClientCommand::List { seat: None },
        },
        15,
    )
    .unwrap();
    assert!(all.contains("seat0"));
    assert!(all.contains("seat1"));
    let selected = admin::seat(
        SeatCommand::Client {
            command: ClientCommand::List {
                seat: Some(seat_udev::SeatName::seat0()),
            },
        },
        15,
    )
    .unwrap();
    assert!(selected.contains("seat0"));
    assert!(!selected.contains("seat1"));
    let revoked = admin::seat(
        SeatCommand::Client {
            command: ClientCommand::Revoke {
                client: CLIENT_ID.into(),
            },
        },
        15,
    )
    .unwrap();
    assert_eq!(revoked, format!("Revoked seat client {CLIENT_ID}.\n"));
    assert!(!revoked.contains("kill"));
    assert!(admin::session(
        SessionCommand::Close {
            session: "0123456789abcdef0123456789abcdef".into()
        },
        15
    )
    .unwrap()
    .contains("Closed session"));
    drop(server);

    let unavailable = admin::seat(SeatCommand::List, 1).unwrap_err();
    assert!(format!("{unavailable:#}").contains("multiseatd service is unavailable"));

    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("test")).unwrap();
    std::fs::create_dir(root.path().join("test/child")).unwrap();
    let listed = admin::scope(
        ScopeCommand::List {
            prefix: Some("test".into()),
        },
        root.path(),
        1,
    )
    .unwrap();
    assert!(listed.contains("test/child"));
}
