use aclad_api::GrantDescription;
use multiseat_api::RefreshDescription;
use sessiond_api::SessionDescription;
use std::fmt::Write;

pub fn seats(seats: &[String]) -> String {
    if seats.is_empty() {
        return "No seats.\n".to_owned();
    }
    let mut output = "SEAT\n".to_owned();
    for seat in seats {
        writeln!(output, "{seat}").expect("writing to String cannot fail");
    }
    output
}

pub fn sessions(sessions: &[SessionDescription]) -> String {
    if sessions.is_empty() {
        return "No sessions.\n".to_owned();
    }
    let session_width = sessions
        .iter()
        .map(|(sid, _)| sid.len())
        .chain(["SESSION".len()])
        .max()
        .expect("heading provides a width");
    let uid_width = sessions
        .iter()
        .map(|(_, uid)| uid.to_string().len())
        .chain(["UID".len()])
        .max()
        .expect("heading provides a width");
    let mut output = String::new();
    writeln!(
        output,
        "{:<session_width$}  {:>uid_width$}",
        "SESSION", "UID"
    )
    .expect("writing to String cannot fail");
    for (sid, uid) in sessions {
        writeln!(output, "{sid:<session_width$}  {uid:>uid_width$}")
            .expect("writing to String cannot fail");
    }
    output
}

pub fn scopes(scopes: &[String]) -> String {
    if scopes.is_empty() {
        return "No matching scopes.\n".to_owned();
    }
    let mut output = "SCOPE\n".to_owned();
    for scope in scopes {
        writeln!(output, "{scope}").expect("writing to String cannot fail");
    }
    output
}

pub fn scope_of(pid: u32, scope: &str) -> String {
    if scope.is_empty() {
        return format!("PID {pid} is not in a managed scope.\n");
    }
    let pid_width = pid.to_string().len().max("PID".len());
    format!("{:>pid_width$}  SCOPE\n{pid:>pid_width$}  {scope}\n", "PID")
}

pub fn grants(grants: &[GrantDescription]) -> String {
    if grants.is_empty() {
        return "No grants.\n".to_owned();
    }
    let session_width = grants
        .iter()
        .map(|(sid, _, _)| sid.len())
        .chain(["SESSION".len()])
        .max()
        .expect("heading provides a width");
    let uid_width = grants
        .iter()
        .map(|(_, uid, _)| uid.to_string().len())
        .chain(["UID".len()])
        .max()
        .expect("heading provides a width");
    let mut output = String::new();
    writeln!(
        output,
        "{:<session_width$}  {:>uid_width$}  SEAT",
        "SESSION", "UID"
    )
    .expect("writing to String cannot fail");
    for (sid, uid, seat) in grants {
        writeln!(output, "{sid:<session_width$}  {uid:>uid_width$}  {seat}")
            .expect("writing to String cannot fail");
    }
    output
}

pub fn refresh_preview(changes: &[RefreshDescription]) -> String {
    if changes.is_empty() {
        return "No seat configuration changes.\n".to_owned();
    }
    let mut output = String::new();
    for (seat, action, old, new) in changes {
        writeln!(output, "{seat}: {action}").expect("writing to String cannot fail");
        writeln!(
            output,
            "  old allowlist: {}",
            if old.is_empty() {
                "(empty)".to_owned()
            } else {
                old.join(", ")
            }
        )
        .expect("writing to String cannot fail");
        writeln!(
            output,
            "  new allowlist: {}",
            if new.is_empty() {
                "(empty)".to_owned()
            } else {
                new.join(", ")
            }
        )
        .expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0123456789abcdef0123456789abcdef";
    const B: &str = "1123456789abcdef0123456789abcdef";

    #[test]
    fn renders_explicit_empty_states() {
        assert_eq!(seats(&[]), "No seats.\n");
        assert_eq!(sessions(&[]), "No sessions.\n");
        assert_eq!(scopes(&[]), "No matching scopes.\n");
        assert_eq!(grants(&[]), "No grants.\n");
        assert_eq!(refresh_preview(&[]), "No seat configuration changes.\n");
    }

    #[test]
    fn renders_aligned_session_and_grant_tables_without_reordering() {
        assert_eq!(
            sessions(&[(B.to_owned(), 7), (A.to_owned(), 1000)]),
            concat!(
                "SESSION                            UID\n",
                "1123456789abcdef0123456789abcdef     7\n",
                "0123456789abcdef0123456789abcdef  1000\n",
            )
        );
        assert_eq!(
            grants(&[
                (B.to_owned(), 7, "seat-long".to_owned()),
                (A.to_owned(), 1000, "seat0".to_owned()),
            ]),
            concat!(
                "SESSION                            UID  SEAT\n",
                "1123456789abcdef0123456789abcdef     7  seat-long\n",
                "0123456789abcdef0123456789abcdef  1000  seat0\n",
            )
        );
    }

    #[test]
    fn renders_scope_lookup_and_refresh_preview() {
        assert_eq!(scope_of(99, ""), "PID 99 is not in a managed scope.\n");
        assert_eq!(
            refresh_preview(&[(
                "seat0".to_owned(),
                "replace".to_owned(),
                vec!["/dev/a".to_owned()],
                vec![],
            )]),
            "seat0: replace\n  old allowlist: /dev/a\n  new allowlist: (empty)\n"
        );
    }
}
