# loginctl

Synchronous administrator for the decoupled login stack. It has no async
runtime. All session queries and close operations use `lib-sessiond`'s authenticated
blocking daemon client; generic scope operations use `lib-scoped` directly.
Seat operations use the corresponding blocking component client. A missing component does not
break unrelated command groups.

The binary never invokes `sudo`. Direct cgroup operations use the caller's
permissions and are not coordinated with sessiond's per-UID effect lanes, so
mutating sessiond-owned scopes can be disruptive.

## Commands

```text
loginctl seat list|status|refresh
loginctl seat context SEAT list
loginctl seat context SEAT show|activate|deactivate|foreground|remove CONTEXT
loginctl seat context SEAT create [--vt VT] [--activate] -- TRUSTED-CONTROLLER [ARGS...]
loginctl seat context SEAT status --authority-fd FD
loginctl seat context SEAT grant|revoke --authority-fd FD UID
loginctl seat disconnect --connection-fd FD
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
Session list needs sessiond, not its configuration or local containment access.
It displays `SESSION`, `UID`, `RUNTIME_DIR`, `MASTER`, `START`; master tracking is
queried separately, with `-` for missing tracking and concurrently removed
sessions omitted. Inventory does not probe liveness or certify readiness.
Session close uses `CloseSession`: only actual session-tree removal prints
success, not Pending/timeouts/errors or later manager/runtime reconciliation.
The daemon authoritatively refuses a waiting caller inside the target subtree.
Typed sessiond errors and named remote categories remain in diagnostics.

Scope IDs are fully qualified: their first segment identifies the explicit
lib-scoped domain. Scope removal is single-node and nonrecursive. Moving a
process and assigning a target are intentionally separate commands. Target
removal only unregisters tracking. `scope watch` waits for subtree emptiness on
the caller thread.

Physical hotplug is continuous, but assignment changes are explicit. Assign,
unassign and flush change persistent rules and trigger udev only; they print an
instruction to run `loginctl seat refresh` separately. They need no participant
configuration or running seat daemons and never implicitly refresh runtime policy.
Refresh validates the complete configured list, then synchronously removes
unassigned devices on ALL reachable configured seats. Only unanimous removal and
unchanged pinned owners permit ANY additions. An offline configured seat blocks
additions; errors preserve partial actual results, with no rollback/automatic
retry. Retire/recover an old owner before omitting it from configuration. Finish
assignments before destination startup; initial enumeration is not a live move.
`seat list` shows configured participants, not bus discovery. Status separates
udev topology, brokered devices, direct-access devices, static direct-access nodes
and persistent assignments. Context IDs are canonical UUIDv7, not credentials;
connection handles are diagnostic socket numbers scoped to a seat/unique owner.
Every context command routes to an explicit seat. Listing and ID-based mutations
require root; activation/deactivation/foreground have no capability variants. Full authority is an inherited FD verified
by multiseatd; it authorizes only that context. Removal does not terminate processes.
`context create` delegates FULL authority to an explicitly trusted controller and
removes the context after its exit; it does not activate unless requested. Never
use that command to pass authority straight into an ordinary desktop application.
Trusted launch code uses seat-launch at the final compositor exec boundary.
`seat flush` removes all managed persistent rules, including offline ones, not
contexts/processes or runtime admission. Follow it with explicit refresh if needed. Connection disconnect
operates on a possessed inherited FD, not a global ID or remote RPC. There is no `acl` command group.

## PAM configuration

`loginctl pam` reads only `/etc/loginctl.conf`. The strict grammar permits
blank lines, whole-line comments, a double-quoted absolute PAM path, and an
optional explicit seat list:

```text
pam_file = "/etc/pam.d/system-login"
seats = "seat0 seat1"
```

Seat movement/listing requires 1–256 unique valid explicit participants. There
is no wildcard, discovery or implicit default pair. Missing/invalid seat lists
do not prevent unrelated session, scope or PAM commands.

Activation inserts the following before the sole active session `pam_env.so`
anchor when no block exists, preserving metadata and a timestamped backup:

```pam
# BEGIN sglogin
session include sessiond-session
# END sglogin
```

An existing well-formed block is replaced **in place**, regardless of edited
interior contents, without requiring an anchor or relocating the block.
Deactivation removes any marked contents. Outside text is preserved. Unmatched,
duplicate or ambiguous boundaries are rejected. Only these markers are
recognized: there is no historical-marker migration.

Loginctl does not read/validate the included fragment, module availability,
required/optional policy, daemon readiness or other sessiond entries. Sessiond
owns the named include: required local core and optional daemon readiness.
Builds/tests never activate installed PAM.

## Development

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
./tests/pam-env.sh
```

The integration test uses a private bus and a disposable arbitrary scope domain.
As a normal user it verifies rejection of a non-root fake seat owner. Run the
already-built `dbus` integration-test executable via sudo (never Cargo as root)
to additionally exercise successful root-owned routing, shared seven-field records,
all-removals-before-additions and offline-participant failure. No test writes
host PAM, assignments or production cgroups.

Library dependencies use public HTTPS Git sources, with exact sessiond 0.2.0
SDK/scoped revisions recorded in Cargo.toml/Cargo.lock. Multiseatd pins are
unchanged. All component clients remain synchronous and executor-free.
