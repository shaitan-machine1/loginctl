#!/bin/sh
# A PRIVATE named include: required core, optional readiness, then pam_env.
# The fixture modules model publication only, not real containment/readiness.
set -eu
for command in cc mktemp; do command -v "$command" >/dev/null || exit 77; done
work=$(mktemp -d /tmp/loginctl-pam-env.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir "$work/pam.d"
cat >"$work/core.c" <<'EOF'
#include <security/pam_modules.h>
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags; (void)argv;
    if (argc) return PAM_SESSION_ERR;
    return pam_putenv(pamh, "XDG_SESSION_ID=0123456789abcdef0123456789abcdef");
}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv; return PAM_SUCCESS;
}
EOF
cat >"$work/ready.c" <<'EOF'
#include <security/pam_modules.h>
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags; (void)argv;
    int status = pam_putenv(pamh, "XDG_RUNTIME_DIR");
    if (status != PAM_SUCCESS) return status;
    if (argc) return PAM_SESSION_ERR;
    return pam_putenv(pamh, "XDG_RUNTIME_DIR=/run/user/4242");
}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv; return PAM_SUCCESS;
}
EOF
cat >"$work/harness.c" <<'EOF'
#include <security/pam_appl.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static int conversation(int count, const struct pam_message **messages, struct pam_response **responses, void *data) {
    (void)count; (void)messages; (void)data; *responses = NULL; return PAM_CONV_ERR;
}
int main(int argc, char **argv) {
    if (argc != 3) return 64;
    struct passwd *entry = getpwuid(getuid()); if (!entry) return 65;
    struct pam_conv conv = {conversation, NULL}; pam_handle_t *pamh = NULL;
    int s = pam_start_confdir("loginctl-test", entry->pw_name, &conv, argv[1], &pamh); if (s) return 1;
    if (pam_putenv(pamh, "XDG_SESSION_ID=stale") || pam_putenv(pamh, "XDG_RUNTIME_DIR=/stale")) return 2;
    s = pam_open_session(pamh, 0);
    int result = 0;
    if (strcmp(argv[2], "core-fail") == 0) result = s == PAM_SUCCESS;
    else if (s != PAM_SUCCESS) result = 3;
    else {
        const char *sid = pam_getenv(pamh, "XDG_SESSION_ID"), *runtime = pam_getenv(pamh, "XDG_RUNTIME_DIR");
        if (!sid || strcmp(sid, "0123456789abcdef0123456789abcdef")) result = 4;
        if (strcmp(argv[2], "ready-fail") == 0) { if (runtime) result = 5; }
        else {
            const char *address = pam_getenv(pamh, "DBUS_SESSION_BUS_ADDRESS");
            if (!runtime || strcmp(runtime, "/run/user/4242") || !address || strcmp(address, "unix:path=/run/user/4242/bus")) result = 6;
        }
    }
    if (s == PAM_SUCCESS && pam_close_session(pamh, 0) != PAM_SUCCESS) result = 7;
    pam_end(pamh, s); return result;
}
EOF
cc -fPIC -shared "$work/core.c" -lpam -o "$work/core.so"
cc -fPIC -shared "$work/ready.c" -lpam -o "$work/ready.so"
cc -Wall -Wextra -Werror "$work/harness.c" -lpam -o "$work/harness"
printf '%s\n' 'session include sessiond-session' "session required pam_env.so conffile=$work/pam_env.conf readenv=0" >"$work/pam.d/loginctl-test"
printf '%s\n' 'DBUS_SESSION_BUS_ADDRESS DEFAULT="unix:path=${XDG_RUNTIME_DIR}/bus"' >"$work/pam_env.conf"
for mode in success ready-fail core-fail; do
    core= ready=
    [ "$mode" != core-fail ] || core=fail
    [ "$mode" != ready-fail ] || ready=fail
    printf '%s\n' "session required $work/core.so $core" "session optional $work/ready.so $ready" >"$work/pam.d/sessiond-session"
    "$work/harness" "$work/pam.d" "$mode"
done
echo 'private named PAM include preserves required-core/optional-readiness publication before pam_env'
