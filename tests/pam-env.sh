#!/bin/sh
# Validate the documented pam_env syntax after an earlier module sets XDG_RUNTIME_DIR.
set -eu
for command in cc mktemp; do
    command -v "$command" >/dev/null || exit 77
done
work=$(mktemp -d /tmp/loginctl-pam-env.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir "$work/pam.d"

cat >"$work/set-runtime.c" <<'EOF'
#include <security/pam_modules.h>
#include <security/pam_ext.h>
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
    (void)flags; (void)argc; (void)argv;
    return pam_putenv(pamh, "XDG_RUNTIME_DIR=/run/user/4242");
}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
EOF
cat >"$work/harness.c" <<'EOF'
#include <security/pam_appl.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static int conversation(int count, const struct pam_message **messages,
                        struct pam_response **responses, void *data) {
    (void)count; (void)messages; (void)responses; (void)data;
    return PAM_CONV_ERR;
}
int main(int argc, char **argv) {
    if (argc != 2) return 64;
    struct passwd *entry = getpwuid(getuid());
    if (entry == NULL) return 65;
    struct pam_conv conv = {conversation, NULL};
    pam_handle_t *pamh = NULL;
    int status = pam_start_confdir("loginctl-test", entry->pw_name, &conv,
                                   argv[1], &pamh);
    if (status == PAM_SUCCESS) status = pam_open_session(pamh, 0);
    const char *raw = status == PAM_SUCCESS
        ? pam_getenv(pamh, "DBUS_SESSION_BUS_ADDRESS") : NULL;
    if (status != PAM_SUCCESS)
        fprintf(stderr, "PAM session failed: %s\n", pam_strerror(pamh, status));
    else if (raw == NULL)
        fprintf(stderr, "pam_env did not set DBUS_SESSION_BUS_ADDRESS\n");
    char value[256] = {0};
    if (raw != NULL) snprintf(value, sizeof(value), "%s", raw);
    if (status == PAM_SUCCESS) status = pam_close_session(pamh, 0);
    pam_end(pamh, status);
    if (status != PAM_SUCCESS || raw == NULL) return 1;
    puts(value);
    return strcmp(value, "unix:path=/run/user/4242/bus") == 0 ? 0 : 2;
}
EOF
cc -fPIC -shared "$work/set-runtime.c" -lpam -o "$work/pam_set_runtime.so"
cc "$work/harness.c" -lpam -o "$work/harness"
printf '%s\n' \
    "session required $work/pam_set_runtime.so" \
    "session required pam_env.so conffile=$work/pam_env.conf readenv=0" \
    >"$work/pam.d/loginctl-test"
printf '%s\n' \
    'DBUS_SESSION_BUS_ADDRESS DEFAULT="unix:path=${XDG_RUNTIME_DIR}/bus"' \
    >"$work/pam_env.conf"
[ "$("$work/harness" "$work/pam.d")" = 'unix:path=/run/user/4242/bus' ]
echo 'pam_env expands XDG_RUNTIME_DIR after the earlier session module'
