use clap::{Parser, Subcommand};
use lib_scoped::{ScopeId, TargetId};
use seat_udev::SeatName;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(version, about = "Administer the decoupled login stack")]
pub struct Args {
    /// Timeout for blocking bus, watch, and udev operations, in seconds.
    #[arg(long, default_value_t = 15)]
    pub timeout_seconds: u64,
    /// Cgroup-v2 mount used by direct scope commands.
    #[arg(long, default_value = "/sys/fs/cgroup")]
    pub cgroup_root: PathBuf,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inspect seats and manage seat assignments.
    Seat {
        #[command(subcommand)]
        command: SeatCommand,
    },
    /// Inspect and close login sessions.
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    /// Inspect and terminate process scopes.
    Scope {
        #[command(subcommand)]
        command: ScopeCommand,
    },
    /// Inspect or change PAM integration.
    Pam {
        #[command(subcommand)]
        command: PamCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum SeatCommand {
    /// List seats managed by multiseatd.
    List,
    /// Show udev seats, devices, and persistent assignments.
    Status,
    /// Inspect or revoke opaque seat client leases (not processes).
    Client {
        #[command(subcommand)]
        command: ClientCommand,
    },
    /// Assign a complete ID_FOR_SEAT device group to a seat.
    Assign { device: PathBuf, seat: SeatName },
    /// Remove the persistent assignment for a device group.
    Unassign { device: PathBuf },
    /// Remove every managed persistent assignment.
    Flush,
}

#[derive(Debug, Subcommand)]
pub enum ClientCommand {
    /// List live seat clients, optionally restricted to one seat.
    List { seat: Option<SeatName> },
    /// Revoke a seat client; this does not kill a process.
    Revoke {
        #[arg(value_parser = parse_client_id)]
        client: String,
    },
}

pub fn parse_client_id(value: &str) -> Result<String, String> {
    match uuid::Uuid::parse_str(value) {
        Ok(id)
            if id.to_string() == value
                && id.get_version_num() == 7
                && id.get_variant() == uuid::Variant::RFC4122 =>
        {
            Ok(value.to_owned())
        }
        _ => Err("client ID must be a canonical UUIDv7".into()),
    }
}

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// List managed sessions.
    List,
    /// Close a session and wait for complete daemon teardown.
    Close {
        #[arg(value_parser = parse_session_id)]
        session: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ScopeCommand {
    /// List scopes below PREFIX (default: sessiond).
    List {
        #[arg(value_parser = parse_scope)]
        prefix: Option<String>,
    },
    /// Show population, identity, and target diagnostics.
    Show {
        #[arg(value_parser = parse_scope)]
        scope: String,
    },
    /// Show the scope containing a process in DOMAIN.
    Of {
        pid: u32,
        #[arg(long, default_value = "sessiond", value_parser = parse_domain)]
        domain: String,
    },
    /// Create one scope node. Its parent must already exist.
    Create {
        #[arg(value_parser = parse_scope)]
        scope: String,
    },
    /// Move a process without assigning a target record.
    Move {
        pid: u32,
        #[arg(value_parser = parse_scope)]
        scope: String,
    },
    /// Remove one empty scope node; never recursive.
    Remove {
        #[arg(value_parser = parse_scope)]
        scope: String,
    },
    /// Send SIGTERM to every process below a scope.
    Terminate {
        #[arg(value_parser = parse_scope)]
        scope: String,
    },
    /// Immediately SIGKILL every process below a scope.
    Kill {
        #[arg(value_parser = parse_scope)]
        scope: String,
    },
    /// Inspect or mutate scoped target records.
    Target {
        #[command(subcommand)]
        command: TargetCommand,
    },
    /// Block until a scope subtree becomes empty or timeout expires.
    Watch {
        #[arg(value_parser = parse_scope)]
        scope: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum TargetCommand {
    List {
        #[arg(value_parser = parse_scope)]
        scope: String,
    },
    Show {
        #[arg(value_parser = parse_scope)]
        scope: String,
        #[arg(value_parser = parse_target)]
        target: String,
    },
    Assign {
        #[arg(value_parser = parse_scope)]
        scope: String,
        #[arg(value_parser = parse_target)]
        target: String,
        pid: u32,
    },
    Remove {
        #[arg(value_parser = parse_scope)]
        scope: String,
        #[arg(value_parser = parse_target)]
        target: String,
    },
    Terminate {
        #[arg(value_parser = parse_scope)]
        scope: String,
        #[arg(value_parser = parse_target)]
        target: String,
    },
    Kill {
        #[arg(value_parser = parse_scope)]
        scope: String,
        #[arg(value_parser = parse_target)]
        target: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum PamCommand {
    /// Report PAM integration status.
    Status,
    /// Activate the managed PAM block.
    Activate,
    /// Deactivate the managed PAM block.
    Deactivate,
}

pub fn parse_session_id(value: &str) -> Result<String, String> {
    if value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(value.to_owned())
    } else {
        Err("session ID must be exactly 32 lowercase hexadecimal digits".to_owned())
    }
}

fn parse_scope(value: &str) -> Result<String, String> {
    ScopeId::parse(value)
        .map(String::from)
        .map_err(|error| error.to_string())
}
fn parse_domain(value: &str) -> Result<String, String> {
    let scope = ScopeId::parse(value).map_err(|error| error.to_string())?;
    if scope.segments().count() == 1 {
        Ok(value.to_owned())
    } else {
        Err("domain must be one portable scope segment".into())
    }
}
fn parse_target(value: &str) -> Result<String, String> {
    TargetId::parse(value)
        .map(String::from)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    const SID: &str = "0123456789abcdef0123456789abcdef";
    const SCOPE: &str = "sessiond/user/1000/session/0123456789abcdef0123456789abcdef";

    #[test]
    fn parses_every_command_group() {
        for args in [
            vec!["loginctl", "seat", "list"],
            vec!["loginctl", "seat", "status"],
            vec!["loginctl", "seat", "client", "list"],
            vec!["loginctl", "seat", "client", "list", "seat0"],
            vec![
                "loginctl",
                "seat",
                "client",
                "revoke",
                "01900000-0000-7000-8000-000000000000",
            ],
            vec!["loginctl", "seat", "assign", "/dev/dri/card0", "seat1"],
            vec!["loginctl", "seat", "unassign", "/dev/dri/card0"],
            vec!["loginctl", "seat", "flush"],
            vec!["loginctl", "session", "list"],
            vec!["loginctl", "session", "close", SID],
            vec!["loginctl", "scope", "list"],
            vec!["loginctl", "scope", "list", "sessiond"],
            vec!["loginctl", "scope", "show", SCOPE],
            vec!["loginctl", "scope", "of", "123", "--domain", "sessiond"],
            vec!["loginctl", "scope", "create", SCOPE],
            vec!["loginctl", "scope", "move", "123", SCOPE],
            vec!["loginctl", "scope", "remove", SCOPE],
            vec!["loginctl", "scope", "terminate", SCOPE],
            vec!["loginctl", "scope", "kill", SCOPE],
            vec!["loginctl", "scope", "target", "list", SCOPE],
            vec!["loginctl", "scope", "target", "show", SCOPE, "leader"],
            vec![
                "loginctl", "scope", "target", "assign", SCOPE, "leader", "123",
            ],
            vec!["loginctl", "scope", "target", "remove", SCOPE, "leader"],
            vec!["loginctl", "scope", "target", "terminate", SCOPE, "leader"],
            vec!["loginctl", "scope", "target", "kill", SCOPE, "leader"],
            vec!["loginctl", "scope", "watch", SCOPE],
            vec!["loginctl", "pam", "status"],
            vec!["loginctl", "pam", "activate"],
            vec!["loginctl", "pam", "deactivate"],
        ] {
            Args::try_parse_from(args).expect("command parses");
        }
    }

    #[test]
    fn rejects_malformed_protocol_arguments() {
        let sid = Args::try_parse_from(["loginctl", "session", "close", "bad"])
            .expect_err("invalid session is rejected");
        assert_eq!(sid.kind(), ErrorKind::ValueValidation);

        let scope = Args::try_parse_from(["loginctl", "scope", "kill", "/absolute"])
            .expect_err("invalid scope is rejected");
        assert_eq!(scope.kind(), ErrorKind::ValueValidation);

        let seat = Args::try_parse_from(["loginctl", "seat", "assign", "/dev/null", "not/a/seat"])
            .expect_err("invalid seat is rejected");
        assert_eq!(seat.kind(), ErrorKind::ValueValidation);
        assert!(Args::try_parse_from(["loginctl", "seat", "refresh"]).is_err());
        assert!(Args::try_parse_from(["loginctl", "acl", "status"]).is_err());
        for id in [
            "bad",
            "01900000-0000-4000-8000-000000000000",
            "01900000-0000-7000-C000-000000000000",
        ] {
            assert!(Args::try_parse_from(["loginctl", "seat", "client", "revoke", id]).is_err());
        }
    }
}
