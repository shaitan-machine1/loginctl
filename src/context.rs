//! Synchronous context/connection administration, separate from process lifetime.
use crate::cli::ContextCommand;
use crate::output;
use anyhow::{bail, Context as _, Result};
use libmultiseatd::Client;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::time::Duration;

fn client(seat: &str, seconds: u64) -> Result<Client> {
    crate::admin::service_call(
        "multiseatd",
        Client::system_with_timeout(seat, Duration::from_secs(seconds.max(1))),
        "connect to configured multiseatd seat",
    )
}
fn authority(raw: i32) -> Result<OwnedFd> {
    if raw < 3 || unsafe { libc::fcntl(raw, libc::F_GETFD) } < 0 {
        bail!("authority must name a live inherited descriptor >= 3")
    }
    let copy = unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) };
    if copy < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(copy) })
}
pub fn contexts(seat: &str, command: ContextCommand, seconds: u64) -> Result<String> {
    let client = client(seat, seconds)?;
    match command {
        ContextCommand::List => Ok(output::contexts(&client.list_contexts()?)),
        ContextCommand::Show { context } => {
            let rows: Vec<_> = client
                .list_contexts()?
                .into_iter()
                .filter(|row| row.id == context)
                .collect();
            if rows.is_empty() {
                bail!("unknown context {context}")
            }
            Ok(output::contexts(&rows))
        }
        ContextCommand::Activate { context } => {
            client.activate_context(context)?;
            Ok(format!("Activated context {context}.\n"))
        }
        ContextCommand::Deactivate { context } => {
            client.deactivate_context(context)?;
            Ok(format!("Deactivated context {context}.\n"))
        }
        ContextCommand::Foreground { context } => {
            client.move_to_foreground(context)?;
            Ok(format!("Foreground context {context}.\n"))
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
            client.add_acl_grant(fd.as_fd(), uid)?;
            Ok(format!("Registered UID {uid}.\n"))
        }
        ContextCommand::Revoke { authority_fd, uid } => {
            let fd = authority(authority_fd)?;
            client.remove_acl_grant(fd.as_fd(), uid)?;
            Ok(format!("Revoked UID {uid}.\n"))
        }
        ContextCommand::Create {
            vt,
            activate,
            command,
        } => {
            let context = client.create_context(vt)?;
            let outcome = (|| -> Result<std::process::ExitStatus> {
                if activate {
                    client.activate_context(context.id)?;
                }
                let raw = context.as_fd().as_raw_fd();
                let mut child = std::process::Command::new(&command[0]);
                child
                    .args(&command[1..])
                    .env("MULTISEATD_AUTHORITY_FD", raw.to_string())
                    .env("MULTISEATD_CONTEXT_ID", context.id.to_string())
                    .env("XDG_SEAT", seat)
                    .env_remove("XDG_VTNR");
                if vt != 0 {
                    child.env("XDG_VTNR", vt.to_string());
                }
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
            let status = match (outcome, cleanup) {
                (Ok(status), Ok(())) => status,
                (Err(error), Ok(())) => return Err(error),
                (Ok(_), Err(error)) => return Err(error.into()),
                (Err(error), Err(cleanup)) => {
                    bail!("{error:#}; context teardown also failed: {cleanup}")
                }
            };
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
pub fn disconnect(raw: i32) -> Result<String> {
    let fd = authority(raw)?;
    libmultiseatd::remove_connection(fd.as_fd())?;
    Ok("Shut down connection; no process was terminated.\n".into())
}
