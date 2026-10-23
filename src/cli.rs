use clap::{Parser, Subcommand};
use scope_id::ScopeId;
use seat_udev::SeatName;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(version, about = "Administer the decoupled login stack")]
pub struct Args {
    /// Timeout for udev assignment operations, in seconds.
    #[arg(long, default_value_t = 15)]
    pub timeout_seconds: u64,
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
    /// Inspect and administer device ACL grants.
    Acl {
        #[command(subcommand)]
        command: AclCommand,
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
    /// Preview and explicitly refresh changed seatd allowlists.
    Refresh {
        seat: Option<SeatName>,
        /// Skip the interactive destructive-operation confirmation.
        #[arg(long)]
        force: bool,
    },
    /// Assign a complete ID_FOR_SEAT device group to a seat.
    Assign { device: PathBuf, seat: SeatName },
    /// Remove the persistent assignment for a device group.
    Unassign { device: PathBuf },
    /// Remove every managed persistent assignment.
    Flush,
}

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// List managed sessions.
    List,
    /// Request asynchronous, idempotent closure of a session.
    Close {
        #[arg(value_parser = parse_session_id)]
        session: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ScopeCommand {
    /// List managed scopes below PREFIX (default: sessiond).
    List {
        #[arg(value_parser = parse_scope)]
        prefix: Option<String>,
    },
    /// Show the managed scope containing a process.
    Of { pid: u32 },
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
}

#[derive(Debug, Subcommand)]
pub enum AclCommand {
    /// List active device ACL grants.
    List,
    /// Grant one user access to one seat for a session.
    Grant {
        #[arg(value_parser = parse_session_id)]
        session: String,
        uid: u32,
        seat: SeatName,
    },
    /// Revoke a session's device ACL grant.
    Revoke {
        #[arg(value_parser = parse_session_id)]
        session: String,
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
            vec!["loginctl", "seat", "refresh", "seat0", "--force"],
            vec!["loginctl", "seat", "assign", "/dev/dri/card0", "seat1"],
            vec!["loginctl", "seat", "unassign", "/dev/dri/card0"],
            vec!["loginctl", "seat", "flush"],
            vec!["loginctl", "session", "list"],
            vec!["loginctl", "session", "close", SID],
            vec!["loginctl", "scope", "list"],
            vec!["loginctl", "scope", "list", "sessiond"],
            vec!["loginctl", "scope", "of", "123"],
            vec!["loginctl", "scope", "terminate", SCOPE],
            vec!["loginctl", "scope", "kill", SCOPE],
            vec!["loginctl", "acl", "list"],
            vec!["loginctl", "acl", "grant", SID, "1000", "seat0"],
            vec!["loginctl", "acl", "revoke", SID],
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

        let seat = Args::try_parse_from(["loginctl", "acl", "grant", SID, "1000", "not/a/seat"])
            .expect_err("invalid seat is rejected");
        assert_eq!(seat.kind(), ErrorKind::ValueValidation);
    }
}
