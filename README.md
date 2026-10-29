# loginctl

Synchronous administrator for the decoupled login stack. It has no async
runtime. Session inventory and scope operations call `lib-sessiond` and
`lib-scoped` directly; daemon-backed seat/session-close calls use blocking
clients owned by the corresponding API crates. A missing component does not
break unrelated command groups.

The binary never invokes `sudo`. Direct cgroup operations use the caller's
permissions and are not coordinated with sessiond's per-UID lifecycle lock, so
mutating sessiond-owned scopes can be disruptive.

## Commands

```text
loginctl seat list|status
loginctl seat client list [SEAT]
loginctl seat client revoke CLIENT
loginctl seat assign DEVICE SEAT
loginctl seat unassign DEVICE
loginctl seat flush
loginctl session list
loginctl session close SESSION

loginctl scope list [PREFIX]
loginctl scope show SCOPE
loginctl scope of PID [--domain DOMAIN]
loginctl scope create SCOPE
loginctl scope move PID SCOPE
loginctl scope remove SCOPE
loginctl scope terminate SCOPE
loginctl scope kill SCOPE
loginctl scope target list SCOPE
loginctl scope target show SCOPE TARGET
loginctl scope target assign SCOPE TARGET PID
loginctl scope target remove SCOPE TARGET
loginctl scope target terminate SCOPE TARGET
loginctl scope target kill SCOPE TARGET
loginctl scope watch SCOPE

loginctl pam status|activate|deactivate
```

`--cgroup-root` selects the cgroup-v2 mount for direct scope commands.
`--timeout-seconds` bounds blocking D-Bus, watch, and assignment operations.
Session list is containment-derived and includes recorded leader PID/start
identity without probing liveness. Session close uses `CloseSessionAndWait` and
refuses to block from the target session or that user's service subtree.

Scope IDs are fully qualified: their first segment identifies the explicit
lib-scoped domain. Scope removal is single-node and nonrecursive. Moving a
process and assigning a target are intentionally separate commands. Target
removal only unregisters tracking. `scope watch` waits for subtree emptiness on
the caller thread.

Seat topology is reconciled continuously by multiseatd; there is no explicit
refresh command. Status separates udev topology, brokered devices, direct-access
devices, static direct-access nodes and persistent assignments. Client IDs are
opaque UUIDv7 leases: revoking one revokes seat access, not a process.
`seat flush` removes persistent assignment rules only; it does not flush daemon
runtime state, revoke clients or clear ACLs. There is no `acl` command group.

## PAM configuration

`loginctl pam` reads only `/etc/loginctl.conf`. The strict grammar permits
blank lines, whole-line comments, and exactly one double-quoted absolute path:

```text
pam_file = "/etc/pam.d/system-login"
```

Activation atomically places the managed block before the sole active session
`pam_env.so` entry while preserving metadata and a timestamped backup.
Malformed, duplicated, partially edited, or ambiguously anchored policies are
rejected rather than repaired implicitly. The managed block and diagnostics
contain only `pam_sessiond.so`. Activation can migrate the exact historical
loginctl-owned two-module block to the sessiond-only block; unrelated PAM ACL
entries are neither detected nor managed.

## Development

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
./tests/pam-env.sh
```

The integration test uses a private bus for the synchronous seat and session
clients and a temporary arbitrary lib-scoped domain.

All library dependencies are standalone Git dependencies over HTTPS:
`lib-multiseatd`/`seat-udev` from the multiseat `v0.2.1` tag and
`lib-scoped`/`lib-sessiond` from sessiond revision `27ef727`. No sibling
checkout or `../` directory layout is required; the pinned revisions are in
`Cargo.lock`.
