//! Synchronous context/connection administration, separate from process lifetime.
use crate::cli::{ConnectionCommand, ContextCommand};
use crate::output;
use anyhow::{bail, Context as _, Result};
use libmultiseatd::Client;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::time::Duration;

fn client(seconds: u64) -> Result<Client> {
    Client::system(Duration::from_secs(seconds)).context("connect to multiseatd")
}
fn authority(raw: i32) -> Result<OwnedFd> {
    if raw < 3 || unsafe { libc::fcntl(raw, libc::F_GETFD) } < 0 {
        bail!("authority must name a live inherited descriptor >= 3")
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}
pub fn contexts(command: ContextCommand, seconds: u64) -> Result<String> {
    let client = client(seconds)?;
    match command {
        ContextCommand::List { seat } => {
            let rows: Vec<_> = client
                .list_contexts()?
                .into_iter()
                .filter(|row| seat.as_ref().is_none_or(|seat| seat.as_str() == row.1))
                .collect();
            Ok(output::contexts(&rows))
        }
        ContextCommand::Show { context } => {
            let rows: Vec<_> = client
                .list_contexts()?
                .into_iter()
                .filter(|row| row.0 == context.to_string())
                .collect();
            if rows.is_empty() {
                bail!("unknown context {context}")
            }
            Ok(output::contexts(&rows))
        }
        ContextCommand::Activate { context } => {
            client.activate_context_by_id(context)?;
            Ok(format!("Activated context {context}.\n"))
        }
        ContextCommand::Deactivate { context } => {
            client.deactivate_context_by_id(context)?;
            Ok(format!("Deactivated context {context}.\n"))
        }
        ContextCommand::Remove { context } => {
            client.remove_context_by_id(context)?;
            Ok(format!(
                "Removed context {context}; no process was terminated.\n"
            ))
        }
        ContextCommand::Status { authority_fd } => {
            let fd = authority(authority_fd)?;
            Ok(output::contexts(&[client.get_context(fd.as_fd())?]))
        }
        ContextCommand::Grant { authority_fd, uid } => {
            let fd = authority(authority_fd)?;
            client.grant_access(fd.as_fd(), uid)?;
            Ok(format!("Registered UID {uid}.\n"))
        }
        ContextCommand::Revoke { authority_fd, uid } => {
            let fd = authority(authority_fd)?;
            client.revoke_access(fd.as_fd(), uid)?;
            Ok(format!("Revoked UID {uid}.\n"))
        }
        ContextCommand::Create {
            seat,
            activate,
            command,
        } => {
            let context = client.create_context(seat.as_str())?;
            let outcome = (|| -> Result<std::process::ExitStatus> {
                if activate {
                    client.activate_context(context.as_fd())?;
                }
                let raw = context.as_fd().as_raw_fd();
                let mut child = std::process::Command::new(&command[0]);
                child
                    .args(&command[1..])
                    .env("MULTISEATD_AUTHORITY_FD", raw.to_string())
                    .env("MULTISEATD_CONTEXT_ID", context.id.to_string());
                // SAFETY: only async-signal-safe descriptor operations occur in
                // the post-fork callback. The target is explicitly trusted with
                // FULL context authority, unlike an ordinary compositor/app.
                unsafe {
                    child.pre_exec(move || {
                        let flags = libc::fcntl(raw, libc::F_GETFD);
                        if flags < 0
                            || libc::fcntl(raw, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
                        {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                child.status().context("launch trusted context controller")
            })();
            let cleanup = client.remove_context_by_id(context.id);
            let status = outcome?;
            cleanup?;
            if !status.success() {
                bail!("trusted context controller exited with {status}")
            }
            Ok(format!(
                "Removed context {} after controller exit.\n",
                context.id
            ))
        }
    }
}
pub fn connections(command: ConnectionCommand, seconds: u64) -> Result<String> {
    let client = client(seconds)?;
    match command {
        ConnectionCommand::List { seat } => {
            let rows: Vec<_> = client
                .list_connections()?
                .into_iter()
                .filter(|row| seat.as_ref().is_none_or(|seat| seat.as_str() == row.2))
                .collect();
            Ok(output::connections(&rows))
        }
        ConnectionCommand::Remove { connection } => {
            client.remove_connection_by_id(connection)?;
            Ok(format!(
                "Removed connection {connection}; no process was terminated.\n"
            ))
        }
    }
}
