use crate::cli::{AclCommand, ScopeCommand, SeatCommand, SessionCommand};
use crate::output;
use aclad_api::ManagerProxy as AcladProxy;
use anyhow::{anyhow, Context, Result};
use multiseat_api::ManagerProxy as MultiseatProxy;
use scoped_api::ManagerProxy as ScopedProxy;
use seat_udev::assign::{Assigner, AssignmentGroup, RealAssignmentBackend};
use seat_udev::{Context as UdevContext, Filter};
use sessiond_api::ManagerProxy as SessiondProxy;
use std::fmt::Write as FmtWrite;
use std::io::{self, Write as IoWrite};
use std::time::Duration;

pub async fn seat(command: SeatCommand, timeout_seconds: u64) -> Result<String> {
    match command {
        SeatCommand::List => {
            let connection = system_bus().await?;
            let proxy = MultiseatProxy::new(&connection)
                .await
                .context("create multiseatd D-Bus proxy")?;
            let seats = service_call(
                "multiseatd",
                proxy.list_seats().await,
                "call multiseatd ListSeats",
            )?;
            Ok(output::seats(&seats))
        }
        SeatCommand::Status => seat_status(timeout_seconds),
        SeatCommand::Refresh { seat, force } => {
            refresh(seat.as_ref().map_or("", seat_udev::SeatName::as_str), force).await
        }
        SeatCommand::Assign { device, seat } => {
            let assigner = assigner(timeout_seconds);
            let group = assigner.assign(&device, &seat).with_context(|| {
                format!("assign device group for {} to {seat}", device.display())
            })?;
            let mut result = format_group("assigned", &group);
            if !group.has_master {
                writeln!(
                    result,
                    "warning: group {} has no master-of-seat device; it cannot create {} alone",
                    group.stable_id, seat
                )
                .expect("writing to String cannot fail");
            }
            Ok(result)
        }
        SeatCommand::Unassign { device } => {
            let group = assigner(timeout_seconds)
                .unassign(&device)
                .with_context(|| format!("unassign device group for {}", device.display()))?;
            Ok(format_group("unassigned", &group))
        }
        SeatCommand::Flush => {
            let groups = assigner(timeout_seconds)
                .flush()
                .context("flush persistent seat assignments")?;
            if groups.is_empty() {
                return Ok("No persistent assignments.\n".to_owned());
            }
            Ok(groups
                .iter()
                .map(|group| format_group("unassigned", group))
                .collect())
        }
    }
}

pub async fn session(command: SessionCommand) -> Result<String> {
    let connection = system_bus().await?;
    let proxy = SessiondProxy::new(&connection)
        .await
        .context("create sessiond D-Bus proxy")?;
    match command {
        SessionCommand::List => {
            let sessions = service_call(
                "sessiond",
                proxy.list_sessions().await,
                "call sessiond ListSessions",
            )?;
            Ok(output::sessions(&sessions))
        }
        SessionCommand::Close { session } => {
            service_call(
                "sessiond",
                proxy.close_session(&session).await,
                &format!("call sessiond CloseSession for {session}"),
            )?;
            Ok(format!("Closure requested for session {session}.\n"))
        }
    }
}

pub async fn scope(command: ScopeCommand) -> Result<String> {
    let connection = system_bus().await?;
    let proxy = ScopedProxy::new(&connection)
        .await
        .context("create scoped D-Bus proxy")?;
    match command {
        ScopeCommand::List { prefix } => {
            let prefix = prefix.as_deref().unwrap_or("sessiond");
            let scopes = service_call(
                "scoped",
                proxy.list(prefix).await,
                &format!("call scoped List for prefix {prefix}"),
            )?;
            Ok(output::scopes(&scopes))
        }
        ScopeCommand::Of { pid } => {
            let scope = service_call(
                "scoped",
                proxy.scope_of(pid).await,
                &format!("call scoped ScopeOf for PID {pid}"),
            )?;
            Ok(output::scope_of(pid, &scope))
        }
        ScopeCommand::Terminate { scope } => {
            service_call(
                "scoped",
                proxy.terminate_scope(&scope).await,
                &format!("call scoped TerminateScope for {scope}"),
            )?;
            Ok(format!("Termination requested for scope {scope}.\n"))
        }
        ScopeCommand::Kill { scope } => {
            service_call(
                "scoped",
                proxy.kill_scope(&scope).await,
                &format!("call scoped KillScope for {scope}"),
            )?;
            Ok(format!("Immediate kill requested for scope {scope}.\n"))
        }
    }
}

pub async fn acl(command: AclCommand) -> Result<String> {
    let connection = system_bus().await?;
    let proxy = AcladProxy::new(&connection)
        .await
        .context("create aclad D-Bus proxy")?;
    match command {
        AclCommand::List => {
            let grants = service_call("aclad", proxy.list_grants().await, "call aclad ListGrants")?;
            Ok(output::grants(&grants))
        }
        AclCommand::Grant { session, uid, seat } => {
            service_call(
                "aclad",
                proxy.grant(&session, uid, seat.as_str()).await,
                &format!("call aclad Grant for session {session}, uid {uid}, seat {seat}"),
            )?;
            Ok(format!(
                "Granted session {session} to uid {uid} on seat {seat}.\n"
            ))
        }
        AclCommand::Revoke { session } => {
            service_call(
                "aclad",
                proxy.revoke(&session).await,
                &format!("call aclad Revoke for session {session}"),
            )?;
            Ok(format!("Revoked session {session}.\n"))
        }
    }
}

async fn refresh(seat: &str, force: bool) -> Result<String> {
    let connection = system_bus().await?;
    let proxy = MultiseatProxy::new(&connection)
        .await
        .context("create multiseatd D-Bus proxy")?;
    let changes = service_call(
        "multiseatd",
        proxy.preview_refresh(seat).await,
        &format_refresh_context("PreviewRefresh", seat),
    )?;
    if changes.is_empty() {
        return Ok(output::refresh_preview(&changes));
    }

    print!("{}", output::refresh_preview(&changes));
    print_known_sessions(&connection).await;
    eprintln!(
        "WARNING: configured devices are seatd allowlists, not devices currently open by clients."
    );
    eprintln!("WARNING: refreshing these seats may terminate graphical sessions.");
    if !force && !confirm()? {
        return Err(anyhow!("refresh cancelled"));
    }

    let completed = service_call(
        "multiseatd",
        proxy.refresh(seat, true).await,
        &format_refresh_context("Refresh", seat),
    )?;
    let mut result = String::new();
    for seat in completed {
        writeln!(result, "refreshed {seat}").expect("writing to String cannot fail");
    }
    Ok(result)
}

async fn print_known_sessions(connection: &zbus::Connection) {
    let Ok(proxy) = SessiondProxy::new(connection).await else {
        return;
    };
    let Ok(sessions) = proxy.list_sessions().await else {
        return;
    };
    if sessions.is_empty() {
        return;
    }
    eprintln!("Known sessions (sessiond cannot yet map these precisely to seats):");
    for (sid, uid) in sessions {
        eprintln!("  {sid} uid={uid}");
    }
}

fn seat_status(timeout_seconds: u64) -> Result<String> {
    let assigner = assigner(timeout_seconds);
    let context = UdevContext::new().context("read udev seat topology")?;
    let mut output = "seats:\n".to_owned();
    for seat in context.seats() {
        writeln!(output, "  {seat}").expect("writing to String cannot fail");
        for device in context.devices(&seat, Filter::All) {
            writeln!(
                output,
                "    {}{}{}",
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
            .expect("writing to String cannot fail");
        }
    }
    output.push_str("persistent assignments:\n");
    for assignment in assigner
        .persisted()
        .context("read persistent seat assignments")?
    {
        writeln!(
            output,
            "  {} -> {} ({})",
            assignment.stable_id,
            assignment.seat,
            assignment.path.display()
        )
        .expect("writing to String cannot fail");
    }
    Ok(output)
}

fn assigner(timeout_seconds: u64) -> Assigner<RealAssignmentBackend> {
    Assigner::new(
        RealAssignmentBackend::system(),
        Duration::from_secs(timeout_seconds),
    )
}

fn format_group(action: &str, group: &AssignmentGroup) -> String {
    let mut output = format!("{action} group {}:\n", group.stable_id);
    for device in &group.devices {
        writeln!(output, "  {}", device.display()).expect("writing to String cannot fail");
    }
    output
}

fn format_refresh_context(method: &str, seat: &str) -> String {
    if seat.is_empty() {
        format!("call multiseatd {method} for all changed seats")
    } else {
        format!("call multiseatd {method} for {seat}")
    }
}

async fn system_bus() -> Result<zbus::Connection> {
    zbus::Connection::system()
        .await
        .context("connect to the system bus")
}

fn service_call<T>(component: &str, result: zbus::Result<T>, context: &str) -> Result<T> {
    result
        .map_err(|error| {
            let rendered = error.to_string();
            if rendered.contains("ServiceUnknown")
                || rendered.contains("NameHasNoOwner")
                || rendered.contains("was not provided by any .service files")
            {
                anyhow!("{component} service is unavailable: {error}")
            } else {
                anyhow!(error)
            }
        })
        .with_context(|| context.to_owned())
}

fn confirm() -> io::Result<bool> {
    eprint!("Continue? [y/N] ");
    io::stderr().flush()?;
    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    Ok(matches!(response.trim(), "y" | "Y" | "yes" | "YES"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_services_get_a_clear_component_error() {
        let error =
            zbus::Error::Failure("org.freedesktop.DBus.Error.ServiceUnknown: no owner".to_owned());
        let rendered = format!(
            "{:#}",
            service_call::<()>("sessiond", Err(error), "call sessiond ListSessions")
                .expect_err("call fails")
        );
        assert!(rendered.contains("call sessiond ListSessions"));
        assert!(rendered.contains("sessiond service is unavailable"));
    }

    #[test]
    fn formats_refresh_context_for_one_or_all_seats() {
        assert_eq!(
            format_refresh_context("Refresh", ""),
            "call multiseatd Refresh for all changed seats"
        );
        assert_eq!(
            format_refresh_context("Refresh", "seat1"),
            "call multiseatd Refresh for seat1"
        );
    }
}
