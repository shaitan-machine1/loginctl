use crate::cli::{AclCommand, ScopeCommand, SeatCommand, SessionCommand, TargetCommand};
use crate::output;
use aclad_api::Client as AcladClient;
use anyhow::{anyhow, Context, Result};
use lib_scoped::{Domain, ScopeId, TargetId, TargetStatus};
use lib_sessiond::bus::Client as SessiondClient;
use lib_sessiond::config::Config as SessionConfig;
use lib_sessiond::SessionCore;
use multiseat_api::Client as MultiseatClient;
use seat_udev::assign::{Assigner, AssignmentGroup, RealAssignmentBackend};
use seat_udev::{Context as UdevContext, Filter};
use std::fmt::Write as FmtWrite;
use std::io::{self, Write as IoWrite};
use std::path::Path;
use std::time::Duration;

pub fn seat(command: SeatCommand, timeout_seconds: u64) -> Result<String> {
    match command {
        SeatCommand::List => {
            let client = MultiseatClient::system(timeout(timeout_seconds))
                .context("connect to the system bus for multiseatd")?;
            let seats = service_call(
                "multiseatd",
                client.list_seats(),
                "call multiseatd ListSeats",
            )?;
            Ok(output::seats(&seats))
        }
        SeatCommand::Status => seat_status(timeout_seconds),
        SeatCommand::Refresh { seat, force } => refresh(
            seat.as_ref().map_or("", seat_udev::SeatName::as_str),
            force,
            timeout_seconds,
        ),
        SeatCommand::Assign { device, seat } => {
            let group = assigner(timeout_seconds)
                .assign(&device, &seat)
                .with_context(|| {
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

pub fn session(command: SessionCommand, timeout_seconds: u64) -> Result<String> {
    match command {
        SessionCommand::List => Ok(output::sessions(&session_core()?.list_sessions()?)),
        SessionCommand::Close { session } => {
            ensure_blocking_close_is_external(&session)?;
            let client = SessiondClient::system(timeout(timeout_seconds))
                .context("connect to the system bus for sessiond")?;
            client
                .close_session(&session)
                .with_context(|| format!("call sessiond CloseSessionAndWait for {session}"))?;
            Ok(format!("Closed session {session}.\n"))
        }
    }
}

pub fn scope(command: ScopeCommand, cgroup_root: &Path, timeout_seconds: u64) -> Result<String> {
    match command {
        ScopeCommand::List { prefix } => {
            let prefix = ScopeId::parse(prefix.as_deref().unwrap_or("sessiond"))?;
            let domain = open_domain(cgroup_root, &prefix)?;
            let scopes = domain
                .list_scopes(&prefix)?
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>();
            Ok(output::scopes(&scopes))
        }
        ScopeCommand::Show { scope } => show_scope(cgroup_root, &ScopeId::parse(scope)?),
        ScopeCommand::Of { pid, domain } => {
            let domain = match Domain::open(cgroup_root, &domain) {
                Ok(domain) => Some(domain),
                Err(error) if error.is_not_found() => None,
                Err(error) => return Err(error.into()),
            };
            let scope = domain
                .as_ref()
                .map(|domain| domain.scope_of(pid))
                .transpose()?
                .flatten();
            Ok(output::scope_of(
                pid,
                scope.as_ref().map_or("", ScopeId::as_str),
            ))
        }
        ScopeCommand::Create { scope } => {
            let scope = ScopeId::parse(scope)?;
            let domain = create_domain(cgroup_root, &scope)?;
            if scope != domain.root_id() {
                domain.create_scope(&scope)?;
            }
            Ok(format!("Created scope {scope}.\n"))
        }
        ScopeCommand::Move { pid, scope } => {
            let scope = ScopeId::parse(scope)?;
            open_domain(cgroup_root, &scope)?.move_process(&scope, pid)?;
            Ok(format!("Moved PID {pid} into {scope}.\n"))
        }
        ScopeCommand::Remove { scope } => {
            let scope = ScopeId::parse(scope)?;
            open_domain(cgroup_root, &scope)?.remove_scope(&scope)?;
            Ok(format!("Removed scope {scope}.\n"))
        }
        ScopeCommand::Terminate { scope } => {
            let scope = ScopeId::parse(scope)?;
            open_domain(cgroup_root, &scope)?.terminate_scope(&scope)?;
            Ok(format!("Sent termination to scope {scope}.\n"))
        }
        ScopeCommand::Kill { scope } => {
            let scope = ScopeId::parse(scope)?;
            open_domain(cgroup_root, &scope)?.kill_scope(&scope)?;
            Ok(format!("Sent immediate kill to scope {scope}.\n"))
        }
        ScopeCommand::Target { command } => target(command, cgroup_root),
        ScopeCommand::Watch { scope } => {
            let scope = ScopeId::parse(scope)?;
            let mut watch = open_domain(cgroup_root, &scope)?.watch_scope(&scope)?;
            if watch.wait_timeout(timeout(timeout_seconds))? {
                Ok(format!("Scope {scope} is empty.\n"))
            } else {
                Ok(format!(
                    "Timed out while scope {scope} remained populated.\n"
                ))
            }
        }
    }
}
fn target(command: TargetCommand, cgroup_root: &Path) -> Result<String> {
    match command {
        TargetCommand::List { scope } => {
            let scope = ScopeId::parse(scope)?;
            let targets = open_domain(cgroup_root, &scope)?.list_targets(&scope)?;
            if targets.is_empty() {
                return Ok("No targets.\n".into());
            }
            let mut result = "TARGET\n".to_owned();
            for target in targets {
                writeln!(result, "{target}").expect("String write");
            }
            Ok(result)
        }
        TargetCommand::Show { scope, target } => show_target(
            cgroup_root,
            &ScopeId::parse(scope)?,
            &TargetId::parse(target)?,
        ),
        TargetCommand::Assign { scope, target, pid } => {
            let scope = ScopeId::parse(scope)?;
            let target = TargetId::parse(target)?;
            open_domain(cgroup_root, &scope)?.assign_target(&scope, &target, pid)?;
            Ok(format!(
                "Assigned target {target} in {scope} to PID {pid}.\n"
            ))
        }
        TargetCommand::Remove { scope, target } => {
            let scope = ScopeId::parse(scope)?;
            let target = TargetId::parse(target)?;
            open_domain(cgroup_root, &scope)?.remove_target(&scope, &target)?;
            Ok(format!("Removed target {target} from {scope}.\n"))
        }
        TargetCommand::Terminate { scope, target } => {
            let scope = ScopeId::parse(scope)?;
            let target = TargetId::parse(target)?;
            open_domain(cgroup_root, &scope)?.terminate_target(&scope, &target)?;
            Ok(format!("Sent termination to target {target} in {scope}.\n"))
        }
        TargetCommand::Kill { scope, target } => {
            let scope = ScopeId::parse(scope)?;
            let target = TargetId::parse(target)?;
            open_domain(cgroup_root, &scope)?.kill_target(&scope, &target)?;
            Ok(format!(
                "Sent immediate kill to target {target} in {scope}.\n"
            ))
        }
    }
}
fn show_scope(cgroup_root: &Path, scope: &ScopeId) -> Result<String> {
    let domain = open_domain(cgroup_root, scope)?;
    let identity = domain
        .scope_identity(scope)?
        .ok_or_else(|| anyhow!("scope {scope} does not exist"))?;
    let populated = domain.scope_populated(scope)?;
    let targets = domain.list_targets(scope)?;
    let mut result = format!(
        "scope: {scope}\ninstance: {}:{}\npopulated: {populated}\ntargets: {}\n",
        identity.device,
        identity.inode,
        targets.len()
    );
    for target in targets {
        let status = domain.target_status(scope, &target)?;
        let membership = domain.target_exists(scope, &target)?;
        writeln!(
            result,
            "  {target}: {} membership={membership}",
            format_target_status(status)
        )
        .expect("String write");
    }
    Ok(result)
}
fn show_target(cgroup_root: &Path, scope: &ScopeId, target: &TargetId) -> Result<String> {
    let domain = open_domain(cgroup_root, scope)?;
    let status = domain.target_status(scope, target)?;
    let membership = domain.target_exists(scope, target)?;
    Ok(format!(
        "scope: {scope}\ntarget: {target}\nstatus: {}\nmembership: {membership}\n",
        format_target_status(status)
    ))
}
fn format_target_status(status: TargetStatus) -> String {
    match status {
        TargetStatus::Untracked => "untracked".into(),
        TargetStatus::Running(identity) => {
            format!("running pid={} start={}", identity.pid, identity.start_time)
        }
        TargetStatus::Exited(identity) => {
            format!("exited pid={} start={}", identity.pid, identity.start_time)
        }
    }
}
fn domain_name(scope: &ScopeId) -> &str {
    scope.segments().next().expect("nonempty scope")
}
fn open_domain(cgroup_root: &Path, scope: &ScopeId) -> Result<Domain> {
    Ok(Domain::open(cgroup_root, domain_name(scope))?)
}
fn create_domain(cgroup_root: &Path, scope: &ScopeId) -> Result<Domain> {
    Ok(Domain::create(cgroup_root, domain_name(scope))?)
}

pub fn acl(command: AclCommand, timeout_seconds: u64) -> Result<String> {
    let client = AcladClient::system(timeout(timeout_seconds))
        .context("connect to the system bus for aclad")?;
    match command {
        AclCommand::List => Ok(output::grants(&service_call(
            "aclad",
            client.list_grants(),
            "call aclad ListGrants",
        )?)),
        AclCommand::Grant { session, uid, seat } => {
            service_call(
                "aclad",
                client.grant(&session, uid, seat.as_str()),
                &format!("call aclad Grant for session {session}, uid {uid}, seat {seat}"),
            )?;
            Ok(format!(
                "Granted session {session} to uid {uid} on seat {seat}.\n"
            ))
        }
        AclCommand::Revoke { session } => {
            service_call(
                "aclad",
                client.revoke(&session),
                &format!("call aclad Revoke for session {session}"),
            )?;
            Ok(format!("Revoked session {session}.\n"))
        }
    }
}
fn refresh(seat: &str, force: bool, timeout_seconds: u64) -> Result<String> {
    let client = MultiseatClient::system(timeout(timeout_seconds))
        .context("connect to the system bus for multiseatd")?;
    let changes = service_call(
        "multiseatd",
        client.preview_refresh(seat),
        &format_refresh_context("PreviewRefresh", seat),
    )?;
    if changes.is_empty() {
        return Ok(output::refresh_preview(&changes));
    }
    print!("{}", output::refresh_preview(&changes));
    print_known_sessions();
    eprintln!(
        "WARNING: configured devices are seatd allowlists, not devices currently open by clients."
    );
    eprintln!("WARNING: refreshing these seats may terminate graphical sessions.");
    if !force && !confirm()? {
        return Err(anyhow!("refresh cancelled"));
    }
    let completed = service_call(
        "multiseatd",
        client.refresh(seat, true),
        &format_refresh_context("Refresh", seat),
    )?;
    let mut result = String::new();
    for seat in completed {
        writeln!(result, "refreshed {seat}").expect("writing to String cannot fail");
    }
    Ok(result)
}
fn print_known_sessions() {
    let Ok(core) = session_core() else {
        return;
    };
    let Ok(sessions) = core.list_sessions() else {
        return;
    };
    if sessions.is_empty() {
        return;
    }
    eprintln!("Known sessions (sessiond cannot yet map these precisely to seats):");
    for session in sessions {
        eprintln!("  {} uid={}", session.id, session.uid);
    }
}
fn session_core() -> Result<SessionCore> {
    let path = Path::new("/etc/sessiond.conf");
    let config = if path.exists() {
        SessionConfig::load(path)?
    } else {
        SessionConfig::default()
    };
    Ok(SessionCore::new(config)?)
}
fn ensure_blocking_close_is_external(sid: &str) -> Result<()> {
    let core = session_core()?;
    let Some(session) = core.find_session(sid)? else {
        return Ok(());
    };
    let domain = match Domain::open(&core.config().cgroup_root, "sessiond") {
        Ok(domain) => domain,
        Err(error) if error.is_not_found() => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let Some(current) = domain.scope_of(std::process::id())? else {
        return Ok(());
    };
    let session_root = lib_scoped::well_known::sessiond_user_session(session.uid, sid)?;
    let service_root = lib_scoped::well_known::sessiond_user_service(session.uid);
    if current.is_or_is_under(&session_root) || current.is_or_is_under(&service_root) {
        return Err(anyhow!(
            "blocking close from {current} could terminate the caller; use a scheduling-only client"
        ));
    }
    Ok(())
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
            .expect("String write");
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
        .expect("String write");
    }
    Ok(output)
}
fn assigner(timeout_seconds: u64) -> Assigner<RealAssignmentBackend> {
    Assigner::new(RealAssignmentBackend::system(), timeout(timeout_seconds))
}
fn timeout(seconds: u64) -> Duration {
    Duration::from_secs(seconds.max(1))
}
fn format_group(action: &str, group: &AssignmentGroup) -> String {
    let mut output = format!("{action} group {}:\n", group.stable_id);
    for device in &group.devices {
        writeln!(output, "  {}", device.display()).expect("String write");
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
fn service_call<T>(
    component: &str,
    result: std::result::Result<T, dbus::Error>,
    context: &str,
) -> Result<T> {
    result
        .map_err(|error| {
            let rendered = error.to_string();
            if matches!(
                error.name(),
                Some(
                    "org.freedesktop.DBus.Error.ServiceUnknown"
                        | "org.freedesktop.DBus.Error.NameHasNoOwner"
                )
            ) || rendered.contains("ServiceUnknown")
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
            dbus::Error::new_custom("org.freedesktop.DBus.Error.ServiceUnknown", "no owner");
        let rendered = format!(
            "{:#}",
            service_call::<()>("sessiond", Err(error), "call sessiond ListSessions").unwrap_err()
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
