# loginctl

`loginctl` is the unified administrator for the decoupled login stack. It uses
the system bus and the typed `multiseat-api`, `sessiond-api`, `scoped-api`, and
`aclad-api` crates directly. Seat assignment uses `seat-udev` directly. The
binary never invokes `sudo`, has no session-bus mode, and leaves authorization
to the daemons (except local PAM-file mutation, which requires an existing root
caller).

## Commands

```text
loginctl seat list
loginctl seat status
loginctl seat refresh [SEAT] [--force]
loginctl seat assign DEVICE SEAT
loginctl seat unassign DEVICE
loginctl seat flush

loginctl session list
loginctl session close SESSION

loginctl scope list [PREFIX]
loginctl scope of PID
loginctl scope terminate SCOPE
loginctl scope kill SCOPE

loginctl acl list
loginctl acl grant SESSION UID SEAT
loginctl acl revoke SESSION

loginctl pam status
loginctl pam activate
loginctl pam deactivate
```

Each daemon-backed command opens only the system-bus proxy it needs. A missing
component therefore does not prevent unrelated command groups from working.
Seat refresh previews allowlist changes, warns about graphical disruption, and
requires confirmation unless `--force` is supplied.

## PAM configuration

`loginctl pam` reads only `/etc/loginctl.conf`. The strict grammar permits
blank lines, whole-line comments, and exactly one double-quoted absolute path:

```text
pam_file = "/etc/pam.d/system-login"
```

There is no command-line path override and no `.toml` filename fallback.
Activation places the exact marked block immediately before the sole active
session `pam_env.so` entry. Mutation uses a sidecar advisory lock, a
same-directory temporary file, fsync, atomic rename, preserved owner/group/mode,
and a timestamped backup. Deactivation removes only the exact marked block.
Malformed, duplicated, partially edited, or ambiguously anchored policies are
rejected instead of repaired implicitly.

The intended `/etc/security/pam_env.conf` entry is:

```text
DBUS_SESSION_BUS_ADDRESS DEFAULT="unix:path=${XDG_RUNTIME_DIR}/bus"
```

This relies on `pam_sessiond.so` running before `pam_env.so`; the user bus
itself remains optional.

## Development

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
./tests/pam-env.sh
```

The D-Bus integration test uses a private bus and verifies that one unavailable
component does not break another command group. The PAM shell test loads the
system's real `pam_env.so` and verifies expansion after an earlier session
module establishes `XDG_RUNTIME_DIR`.
