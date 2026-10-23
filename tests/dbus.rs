use loginctl::admin;
use loginctl::cli::{AclCommand, ScopeCommand, SeatCommand, SessionCommand};
use multiseat_api::RefreshDescription;
use std::process::Command;

struct PrivateBus {
    pid: i32,
    old_address: Option<String>,
}

impl PrivateBus {
    fn start() -> Self {
        let output = Command::new("dbus-daemon")
            .args(["--session", "--fork", "--print-address=1", "--print-pid=1"])
            .output()
            .expect("start private dbus-daemon");
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).expect("D-Bus output is UTF-8");
        let mut lines = stdout.lines();
        let address = lines.next().expect("D-Bus address").to_owned();
        let pid = lines
            .next()
            .expect("D-Bus PID")
            .parse()
            .expect("numeric D-Bus PID");
        let old_address = std::env::var("DBUS_SYSTEM_BUS_ADDRESS").ok();
        std::env::set_var("DBUS_SYSTEM_BUS_ADDRESS", address);
        Self { pid, old_address }
    }
}

impl Drop for PrivateBus {
    fn drop(&mut self) {
        if let Some(address) = &self.old_address {
            std::env::set_var("DBUS_SYSTEM_BUS_ADDRESS", address);
        } else {
            std::env::remove_var("DBUS_SYSTEM_BUS_ADDRESS");
        }
        // SAFETY: kill has no memory-safety preconditions and the saved PID is numeric.
        unsafe {
            libc::kill(self.pid, libc::SIGTERM);
        }
    }
}

struct Sessions;

#[zbus::interface(name = "org.decoupling.sessiond1.Manager")]
impl Sessions {
    async fn list_sessions(&self) -> Vec<(String, u32)> {
        vec![("0123456789abcdef0123456789abcdef".to_owned(), 1000)]
    }

    async fn close_session(&self, _sid: &str) {}
}

struct Seats;

#[zbus::interface(name = "org.decoupling.multiseatd1.Manager")]
impl Seats {
    async fn list_seats(&self) -> Vec<String> {
        vec!["seat0".to_owned()]
    }

    async fn preview_refresh(&self, _seat: &str) -> Vec<RefreshDescription> {
        Vec::new()
    }

    async fn refresh(&self, _seat: &str, _confirmed: bool) -> Vec<String> {
        Vec::new()
    }
}

struct Scopes;

#[zbus::interface(name = "org.decoupling.scoped1.Manager")]
impl Scopes {
    async fn list(&self, prefix: &str) -> Vec<String> {
        vec![format!("{prefix}/user/1000")]
    }

    async fn scope_of(&self, pid: u32) -> String {
        format!("sessiond/process/{pid}")
    }

    async fn terminate_scope(&self, _scope: &str) {}

    async fn kill_scope(&self, _scope: &str) {}
}

struct Acls;

#[zbus::interface(name = "org.decoupling.aclad1.Manager")]
impl Acls {
    async fn list_grants(&self) -> Vec<(String, u32, String)> {
        vec![(
            "0123456789abcdef0123456789abcdef".to_owned(),
            1000,
            "seat0".to_owned(),
        )]
    }

    async fn grant(&self, _sid: &str, _uid: u32, _seat: &str) {}

    async fn revoke(&self, _sid: &str) {}
}

#[test]
fn commands_use_typed_system_bus_apis_and_absent_components_are_isolated() {
    let _bus = PrivateBus::start();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let address = std::env::var("DBUS_SYSTEM_BUS_ADDRESS").expect("private bus address");
        let server = zbus::connection::Builder::address(address.as_str())
            .build()
            .await
            .expect("server connection");

        server
            .object_server()
            .at(sessiond_api::OBJECT_PATH, Sessions)
            .await
            .expect("serve session API");
        server
            .request_name(sessiond_api::BUS_NAME)
            .await
            .expect("own sessiond name");

        assert!(admin::session(SessionCommand::List)
            .await
            .expect("session listing remains available")
            .contains("1000"));
        let unavailable = admin::acl(AclCommand::List)
            .await
            .expect_err("aclad is absent");
        assert!(format!("{unavailable:#}").contains("aclad service is unavailable"));

        server
            .object_server()
            .at(multiseat_api::OBJECT_PATH, Seats)
            .await
            .expect("serve seat API");
        server
            .object_server()
            .at(scoped_api::OBJECT_PATH, Scopes)
            .await
            .expect("serve scope API");
        server
            .object_server()
            .at(aclad_api::OBJECT_PATH, Acls)
            .await
            .expect("serve ACL API");
        for name in [
            multiseat_api::BUS_NAME,
            scoped_api::BUS_NAME,
            aclad_api::BUS_NAME,
        ] {
            server.request_name(name).await.expect("own component name");
        }

        assert_eq!(
            admin::seat(SeatCommand::List, 15).await.unwrap(),
            "SEAT\nseat0\n"
        );
        assert_eq!(
            admin::seat(
                SeatCommand::Refresh {
                    seat: None,
                    force: true,
                },
                15,
            )
            .await
            .unwrap(),
            "No seat configuration changes.\n"
        );
        assert!(admin::scope(ScopeCommand::List { prefix: None })
            .await
            .unwrap()
            .contains("sessiond/user/1000"));
        assert!(admin::scope(ScopeCommand::Of { pid: 42 })
            .await
            .unwrap()
            .contains("sessiond/process/42"));
        assert!(admin::scope(ScopeCommand::Terminate {
            scope: "sessiond/user/1000".to_owned(),
        })
        .await
        .unwrap()
        .contains("Termination requested"));
        assert!(admin::scope(ScopeCommand::Kill {
            scope: "sessiond/user/1000".to_owned(),
        })
        .await
        .unwrap()
        .contains("Immediate kill requested"));
        assert!(admin::acl(AclCommand::List)
            .await
            .unwrap()
            .contains("seat0"));
        assert!(admin::acl(AclCommand::Grant {
            session: "0123456789abcdef0123456789abcdef".to_owned(),
            uid: 1000,
            seat: seat_udev::SeatName::parse("seat0").unwrap(),
        })
        .await
        .unwrap()
        .contains("Granted session"));
        assert!(admin::acl(AclCommand::Revoke {
            session: "0123456789abcdef0123456789abcdef".to_owned(),
        })
        .await
        .unwrap()
        .contains("Revoked session"));
        assert!(admin::session(SessionCommand::Close {
            session: "0123456789abcdef0123456789abcdef".to_owned(),
        })
        .await
        .unwrap()
        .contains("Closure requested"));
    });
}
