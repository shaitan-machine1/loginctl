use dbus::blocking::Connection;
use dbus::channel::MatchingReceiver;
use dbus::message::MatchRule;
use dbus_crossroads::Crossroads;
use loginctl::admin;
use loginctl::cli::{AclCommand, ScopeCommand, SeatCommand, SessionCommand};
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
        for name in [
            lib_sessiond::bus::BUS_NAME,
            multiseat_api::BUS_NAME,
            aclad_api::BUS_NAME,
        ] {
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
        let seats = crossroads.register(multiseat_api::INTERFACE_NAME, |builder| {
            builder.method("ListSeats", (), ("seats",), |_, _, ()| {
                Ok((vec!["seat0".to_owned()],))
            });
            builder.method(
                "PreviewRefresh",
                ("seat",),
                ("changes",),
                |_, _, (_seat,): (String,)| Ok((Vec::<multiseat_api::RefreshDescription>::new(),)),
            );
            builder.method(
                "Refresh",
                ("seat", "confirmed"),
                ("seats",),
                |_, _, (_seat, _): (String, bool)| Ok((Vec::<String>::new(),)),
            );
        });
        let acls = crossroads.register(aclad_api::INTERFACE_NAME, |builder| {
            builder.method("ListGrants", (), ("grants",), |_, _, ()| {
                Ok((vec![(
                    "0123456789abcdef0123456789abcdef".to_owned(),
                    1000u32,
                    "seat0".to_owned(),
                )],))
            });
            builder.method(
                "Grant",
                ("sid", "uid", "seat"),
                (),
                |_, _, (_sid, _uid, _seat): (String, u32, String)| Ok(()),
            );
            builder.method("Revoke", ("sid",), (), |_, _, (_sid,): (String,)| Ok(()));
        });
        crossroads.insert(lib_sessiond::bus::OBJECT_PATH, &[session], ());
        crossroads.insert(multiseat_api::OBJECT_PATH, &[seats], ());
        crossroads.insert(aclad_api::OBJECT_PATH, &[acls], ());
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
    assert_eq!(
        admin::seat(
            SeatCommand::Refresh {
                seat: None,
                force: true
            },
            15
        )
        .unwrap(),
        "No seat configuration changes.\n"
    );
    assert!(admin::acl(AclCommand::List, 15).unwrap().contains("seat0"));
    assert!(admin::acl(
        AclCommand::Grant {
            session: "0123456789abcdef0123456789abcdef".into(),
            uid: 1000,
            seat: seat_udev::SeatName::parse("seat0").unwrap()
        },
        15
    )
    .unwrap()
    .contains("Granted session"));
    assert!(admin::acl(
        AclCommand::Revoke {
            session: "0123456789abcdef0123456789abcdef".into()
        },
        15
    )
    .unwrap()
    .contains("Revoked session"));
    assert!(admin::session(
        SessionCommand::Close {
            session: "0123456789abcdef0123456789abcdef".into()
        },
        15
    )
    .unwrap()
    .contains("Closed session"));
    drop(server);

    let unavailable = admin::acl(AclCommand::List, 1).unwrap_err();
    assert!(format!("{unavailable:#}").contains("aclad service is unavailable"));

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
