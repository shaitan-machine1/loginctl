use dbus::blocking::Connection;
use dbus::channel::MatchingReceiver;
use dbus::message::MatchRule;
use dbus_crossroads::Crossroads;
use loginctl::{
    admin,
    cli::{ContextCommand, ScopeCommand, SeatCommand, SessionCommand},
    config::Config,
};
use std::os::fd::{AsFd, AsRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
const CONTEXT_ID: &str = "01900000-0000-7000-8000-000000000002";
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
        // One integration test in this process, restored after all connections.
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
    fn start(seat: &str, events: Arc<Mutex<Vec<String>>>) -> Self {
        let connection = Connection::new_system().unwrap();
        connection
            .request_name(libmultiseatd::bus_name(seat).unwrap(), false, false, true)
            .unwrap();
        if seat == "seat0" {
            connection
                .request_name(lib_sessiond::bus::BUS_NAME, false, false, true)
                .unwrap();
        }
        let mut crossroads = Crossroads::new();
        let session = crossroads.register(lib_sessiond::bus::INTERFACE_NAME, |builder| {
            builder.method(
                "CloseSessionAndWait",
                ("sid",),
                (),
                |_, _, (_sid,): (String,)| Ok(()),
            );
        });
        let seat = seat.to_owned();
        let seats = crossroads.register(libmultiseatd::INTERFACE_NAME, |builder| {
            builder.method("ListContexts", (), ("contexts",), |_, _, ()| {
                Ok((vec![libmultiseatd::ContextInfo {
                    id: CONTEXT_ID.parse().unwrap(),
                    vt: 7,
                    desired_uids: vec![1000],
                    connection_handles: vec![1],
                    active: true,
                    foreground: true,
                    effective: true,
                }],))
            });
            builder.method(
                "CreateContext",
                ("vt",),
                ("authority", "id"),
                |_, peers: &mut Vec<UnixStream>, (vt,): (u32,)| {
                    assert_eq!(vt, 7);
                    let (endpoint, peer) = UnixStream::pair().unwrap();
                    peers.push(peer);
                    Ok((
                        unsafe { dbus::arg::OwnedFd::new(endpoint.into_raw_fd()) },
                        CONTEXT_ID.to_owned(),
                    ))
                },
            );
            builder.method(
                "CreateConnection",
                ("authority",),
                ("endpoint", "handle"),
                |_, peers: &mut Vec<UnixStream>, (_authority,): (dbus::arg::OwnedFd,)| {
                    let (endpoint, peer) = UnixStream::pair().unwrap();
                    peers.push(peer);
                    Ok((
                        unsafe { dbus::arg::OwnedFd::new(endpoint.into_raw_fd()) },
                        1u32,
                    ))
                },
            );
            for method in [
                "ActivateContext",
                "DeactivateContext",
                "MoveToForeground",
                "RemoveContextById",
            ] {
                builder.method(method, ("id",), (), |_, _, (id,): (String,)| {
                    assert_eq!(id, CONTEXT_ID);
                    Ok(())
                });
            }
            for (method, stage) in [
                ("RemoveUnassignedDevices", "remove"),
                ("AddAssignedDevices", "add"),
            ] {
                let events = events.clone();
                let seat = seat.clone();
                builder.method(method, (), (), move |_, _, ()| {
                    events.lock().unwrap().push(format!("{stage}:{seat}"));
                    Ok(())
                });
            }
        });
        crossroads.insert(
            lib_sessiond::bus::OBJECT_PATH,
            &[session],
            Vec::<UnixStream>::new(),
        );
        crossroads.insert(
            libmultiseatd::OBJECT_PATH,
            &[seats],
            Vec::<UnixStream>::new(),
        );
        connection.start_receive(
            MatchRule::new_method_call(),
            Box::new(move |message, connection| {
                crossroads.handle_message(message, connection).unwrap();
                true
            }),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = std::thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
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
fn explicit_routing_refresh_root_owner_and_unchanged_session_scope_clients() {
    let _bus = PrivateBus::start();
    let events = Arc::new(Mutex::new(Vec::new()));
    let first = Server::start("seat0", events.clone());
    let second = Server::start("seat1", events.clone());
    let config =
        Config::parse("pam_file = \"/etc/pam.d/system-login\"\nseats = \"seat0 seat1\"").unwrap();
    assert_eq!(
        admin::seat_with_config(SeatCommand::List, 2, &config).unwrap(),
        "CONFIGURED SEAT\nseat0\nseat1\n"
    );
    let invalid = Config::parse("pam_file = \"/etc/pam.d/system-login\"\nseats = \"*\"").unwrap();
    let rejected = admin::seat_with_config(SeatCommand::Refresh, 2, &invalid).unwrap_err();
    assert!(format!("{rejected:#}").contains("invalid configured seat"));
    assert!(events.lock().unwrap().is_empty());
    if unsafe { libc::geteuid() } == 0 {
        let client =
            libmultiseatd::Client::system_with_timeout("seat0", Duration::from_secs(2)).unwrap();
        let context = client.create_context(7).unwrap();
        assert_eq!(context.id.to_string(), CONTEXT_ID);
        let connection = client.create_connection(context.as_fd()).unwrap();
        assert_eq!(connection.handle, 1);
        assert_ne!(
            unsafe { libc::fcntl(connection.as_fd().as_raw_fd(), libc::F_GETFD) }
                & libc::FD_CLOEXEC,
            0
        );
        let listed = admin::seat(
            SeatCommand::Context {
                seat: seat_udev::SeatName::seat0(),
                command: ContextCommand::List,
            },
            2,
        )
        .unwrap();
        assert!(listed.contains("true  true  true  1"));
        assert!(!listed.contains("PHASE"));
        for command in [
            ContextCommand::Activate {
                context: context.id,
            },
            ContextCommand::Deactivate {
                context: context.id,
            },
            ContextCommand::Foreground {
                context: context.id,
            },
        ] {
            admin::seat(
                SeatCommand::Context {
                    seat: seat_udev::SeatName::seat0(),
                    command,
                },
                2,
            )
            .unwrap();
        }
        assert_eq!(
            admin::seat_with_config(SeatCommand::Refresh, 2, &config).unwrap(),
            "Refreshed all configured seats.\n"
        );
        assert_eq!(
            *events.lock().unwrap(),
            ["remove:seat0", "remove:seat1", "add:seat0", "add:seat1"]
        );
        drop(second);
        events.lock().unwrap().clear();
        let error = admin::seat_with_config(SeatCommand::Refresh, 2, &config).unwrap_err();
        let failure = error.downcast_ref::<libmultiseatd::RefreshError>().unwrap();
        assert!(!failure.addition_started);
        assert_eq!(*events.lock().unwrap(), ["remove:seat0"]);
    } else {
        let client = libmultiseatd::Client::system("seat0")
            .err()
            .expect("nonroot mock must not impersonate root service");
        assert_eq!(
            client.name().and_then(libmultiseatd::ErrorKind::from_name),
            Some(libmultiseatd::ErrorKind::NotAuthorized)
        );
        drop(second);
    }
    let (endpoint, peer) = UnixStream::pair().unwrap();
    assert!(admin::seat(
        SeatCommand::Disconnect {
            connection_fd: endpoint.as_raw_fd()
        },
        1
    )
    .unwrap()
    .contains("no process was terminated"));
    let mut byte = [0];
    assert_eq!(std::io::Read::read(&mut &peer, &mut byte).unwrap(), 0);
    assert!(admin::session(
        SessionCommand::Close {
            session: "0123456789abcdef0123456789abcdef".into()
        },
        2
    )
    .unwrap()
    .contains("Closed session"));
    drop(first);
    let unavailable = admin::seat(
        SeatCommand::Context {
            seat: seat_udev::SeatName::seat0(),
            command: ContextCommand::List,
        },
        1,
    )
    .unwrap_err();
    assert!(format!("{unavailable:#}").contains("multiseatd service is unavailable"));
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("test")).unwrap();
    std::fs::create_dir(root.path().join("test/child")).unwrap();
    assert!(admin::scope(
        ScopeCommand::List {
            prefix: Some("test".into())
        },
        root.path(),
        1
    )
    .unwrap()
    .contains("test/child"));
}
