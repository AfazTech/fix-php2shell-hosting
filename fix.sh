#!/usr/bin/env bash
set -uo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] Run this script as root." >&2
    exit 1
fi

TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/root/server-hardening-backup-${TS}"
RULE_ID="501500"
RULE_DIR="/etc/custom_modsecurity.d"
RULE_FILE="${RULE_DIR}/infraguard.conf"
CUSTOMBUILD="/usr/local/directadmin/custombuild"

DONE=()
ALREADY=()
SKIPPED=()
FAILED=()

# Restarts needed because we changed something (already confirmed by the user)
RESTART_WEB=0
RESTART_CPSRVD=0
RESTART_DA=0
RESTART_CSF=0

# Restarts only suggested because the step was already applied earlier
SUGGEST_WEB=0
SUGGEST_CPSRVD=0
SUGGEST_DA=0
SUGGEST_CSF=0

MODSEC_INCLUDE_FILE=""
USE_INCLUDE=1
RULE_EXISTED=0

info()   { printf '\033[1;34m[INFO]\033[0m %s\n' "$*"; }
reason() { printf '\033[1;33m[WHY]\033[0m  %s\n' "$*"; }
warn()   { printf '\033[1;31m[WARN]\033[0m %s\n' "$*" >&2; }
ok()     { printf '\033[1;32m[OK]\033[0m   %s\n' "$*"; }
alarm()  { printf '\033[1;41m[ALARM]\033[0m %s\n' "$*" >&2; }
header() { printf '\n\033[1m==== %s ====\033[0m\n' "$1"; }

# Accepts only y (do it) or s (skip)
ask() {
    local ans
    while true; do
        read -r -p "$1 [y/s]: " ans || { echo; warn "Input closed."; exit 1; }
        case "${ans,,}" in
            y) return 0 ;;
            s) return 1 ;;
            *) echo "Enter y (do it) or s (skip)." ;;
        esac
    done
}

# Backup a file/dir, keeping its full path inside the backup dir
backup_path() {
    local src="$1"
    [[ -e "$src" ]] || return 0
    mkdir -p "$BACKUP_DIR" && cp -a --parents "$src" "$BACKUP_DIR/"
}

# ---------- Detect control panel ----------
if [[ -d /usr/local/cpanel ]]; then
    PANEL="cpanel"
elif [[ -d /usr/local/directadmin ]]; then
    PANEL="directadmin"
else
    echo "[ERROR] Neither cPanel nor DirectAdmin was detected." >&2
    exit 1
fi

# ---------- Detect web server ----------
WEBSERVER=""
SERVICE=""
detect_web() {
    [[ -n "$SERVICE" ]] && return 0
    if systemctl is-active --quiet lshttpd; then
        WEBSERVER="LiteSpeed"; SERVICE="lshttpd"
    elif systemctl is-active --quiet litespeed; then
        WEBSERVER="LiteSpeed"; SERVICE="litespeed"
    elif systemctl is-active --quiet httpd; then
        WEBSERVER="Apache"; SERVICE="httpd"
    elif systemctl is-active --quiet apache2; then
        WEBSERVER="Apache"; SERVICE="apache2"
    else
        return 1
    fi
}

# Is the Apache ModSecurity module loaded?
modsec_loaded() {
    local bin
    for bin in httpd apachectl apache2ctl; do
        if command -v "$bin" >/dev/null 2>&1; then
            "$bin" -M 2>/dev/null | grep -qi 'security2_module' && return 0
        fi
    done
    return 1
}

# Apache-compatible config test command
get_test_cmd() {
    if command -v apachectl >/dev/null 2>&1; then
        TEST_CMD=(apachectl -t)
    elif [[ -x /usr/local/apache/bin/httpd ]]; then
        TEST_CMD=(/usr/local/apache/bin/httpd -t)
    elif command -v httpd >/dev/null 2>&1; then
        TEST_CMD=(httpd -t)
    else
        return 1
    fi
}

info "Detected control panel: ${PANEL}"
info "Backup directory: ${BACKUP_DIR}"

# =====================================================
# cPanel: disable phpMyAdmin
# =====================================================
phpmyadmin_already() {
    local f count=0
    for f in /var/cpanel/features/*; do
        [[ -f "$f" ]] || continue
        count=$((count + 1))
        grep -q '^phpmyadmin=0[[:space:]]*$' "$f" || return 1
    done
    [[ "$count" -gt 0 ]]
}

step_phpmyadmin() {
    header "Disable phpMyAdmin (cPanel feature lists)"
    if phpmyadmin_already; then
        ok "Already done: phpmyadmin=0 in all feature lists."
        ALREADY+=("phpMyAdmin already disabled in all feature lists")
        SUGGEST_CPSRVD=1
        return
    fi
    reason "phpMyAdmin is written in PHP, so any PHP bug becomes a risk to the server. Setting it to 0 in every feature list removes it for all accounts."
    if ! ask "Disable phpMyAdmin in all feature lists?"; then
        SKIPPED+=("Disable phpMyAdmin"); return
    fi
    info "Backing up /var/cpanel/features ..."
    if ! backup_path /var/cpanel/features; then
        warn "Backup failed. No changes made."
        FAILED+=("phpMyAdmin (backup failed)"); return
    fi
    local f
    for f in /var/cpanel/features/*; do
        [[ -f "$f" ]] || continue
        if grep -q '^phpmyadmin=' "$f"; then
            sed -i 's/^phpmyadmin=.*/phpmyadmin=0/' "$f"
        else
            [[ -n "$(tail -c1 "$f" 2>/dev/null)" ]] && echo >> "$f"
            echo 'phpmyadmin=0' >> "$f"
        fi
    done
    info "Verification:"
    grep -Hn '^phpmyadmin=' /var/cpanel/features/* || true
    DONE+=("phpmyadmin=0 set in all cPanel feature lists")
    RESTART_CPSRVD=1
}

# =====================================================
# cPanel: disable Roundcube
# =====================================================
step_roundcube() {
    header "Disable Roundcube (cPanel)"
    local cfg="/var/cpanel/cpanel.config"
    if [[ ! -f "$cfg" ]]; then
        warn "${cfg} not found."
        FAILED+=("Roundcube (config file missing)"); return
    fi
    if grep -q '^skiproundcube=1[[:space:]]*$' "$cfg"; then
        ok "Already done: skiproundcube=1."
        ALREADY+=("Roundcube already disabled (skiproundcube=1)")
        SUGGEST_CPSRVD=1
        return
    fi
    reason "Roundcube is written in PHP too, so it has the same exposure to PHP bugs. skiproundcube=1 disables it server-wide."
    if ! ask "Disable Roundcube?"; then
        SKIPPED+=("Disable Roundcube"); return
    fi
    if ! backup_path "$cfg"; then
        warn "Backup failed. No changes made."
        FAILED+=("Roundcube (backup failed)"); return
    fi
    if grep -q '^skiproundcube=' "$cfg"; then
        sed -i 's/^skiproundcube=.*/skiproundcube=1/' "$cfg"
    else
        [[ -n "$(tail -c1 "$cfg")" ]] && echo >> "$cfg"
        echo 'skiproundcube=1' >> "$cfg"
    fi
    grep -n '^skiproundcube=' "$cfg" || true
    DONE+=("skiproundcube=1 set in cpanel.config")
    RESTART_CPSRVD=1
}

# =====================================================
# DirectAdmin: close the panel port in CSF
# =====================================================
step_csf_da_port() {
    header "Close DirectAdmin port in CSF (TCP_IN)"
    local csf_conf="/etc/csf/csf.conf"
    local da_conf="/usr/local/directadmin/conf/directadmin.conf"
    if [[ ! -f "$csf_conf" ]]; then
        warn "CSF is not installed (${csf_conf} not found)."
        FAILED+=("CSF (not installed)"); return
    fi
    local da_port
    da_port="$(awk -F= '/^[[:space:]]*port[[:space:]]*=/ {
        gsub(/[[:space:]]/, "", $2); p=$2
    } END { print (p != "" ? p : "22222") }' "$da_conf" 2>/dev/null)"
    [[ "$da_port" =~ ^[0-9]+$ ]] || da_port="22222"
    info "DirectAdmin port: ${da_port}"

    local line list
    line="$(grep -m1 '^TCP_IN[[:space:]]*=' "$csf_conf" || true)"
    if [[ -z "$line" ]]; then
        warn "TCP_IN not found in ${csf_conf}."
        FAILED+=("CSF (TCP_IN not found)"); return
    fi
    list="$(sed -E 's/^[^"]*"([^"]*)".*/\1/' <<<"$line" | tr -d ' ')"
    if ! grep -q ",${da_port}," <<<",${list},"; then
        ok "Already done: port ${da_port} is not in TCP_IN."
        ALREADY+=("Port ${da_port} already absent from TCP_IN in CSF")
        SUGGEST_CSF=1
        SUGGEST_DA=1
        return
    fi

    reason "DirectAdmin, phpMyAdmin and Roundcube are all written in PHP. Closing the DirectAdmin port removes public access to all three at once, so no separate steps are needed. Make sure you still have another way in (allowed IP / SSH)."
    if ! ask "Remove the DirectAdmin port from TCP_IN?"; then
        SKIPPED+=("Close DirectAdmin port in CSF"); return
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        warn "python3 not found."
        FAILED+=("CSF (python3 missing)"); return
    fi
    if ! backup_path "$csf_conf"; then
        warn "Backup failed. No changes made."
        FAILED+=("CSF (backup failed)"); return
    fi

    DA_PORT="$da_port" python3 - <<'PY'
import os, re
from pathlib import Path

path = Path("/etc/csf/csf.conf")
port = os.environ["DA_PORT"]
content = path.read_text()
pattern = re.compile(r'^(TCP_IN\s*=\s*")([^"]*)(".*)$', re.M)

def update(m):
    ports = [p.strip() for p in m.group(2).split(",") if p.strip()]
    ports = [p for p in ports if p != port]
    return m.group(1) + ",".join(ports) + m.group(3)

updated, count = pattern.subn(update, content, count=1)
if count == 0:
    raise SystemExit("TCP_IN not found. No changes made.")
path.write_text(updated)
PY
    if [[ $? -ne 0 ]]; then
        warn "Update failed. Backup is in ${BACKUP_DIR}"
        FAILED+=("CSF (update failed)"); return
    fi
    grep '^TCP_IN[[:space:]]*=' "$csf_conf" || true
    DONE+=("Port ${da_port} removed from TCP_IN in CSF")
    RESTART_CSF=1
    RESTART_DA=1
}

# =====================================================
# ModSecurity: install the module if missing
# =====================================================
install_modsec_directadmin() {
    if [[ ! -x "${CUSTOMBUILD}/build" ]]; then
        warn "CustomBuild not found at ${CUSTOMBUILD}."
        return 1
    fi
    info "Backing up CustomBuild options and Apache config..."
    backup_path "${CUSTOMBUILD}/options.conf" || return 1
    backup_path /etc/httpd/conf || return 1

    cd "$CUSTOMBUILD" || return 1
    info "Running: ./build update"
    ./build update || return 1
    info "Running: ./build set modsecurity yes"
    ./build set modsecurity yes || return 1
    info "Running: ./build modsecurity (this can take several minutes)"
    ./build modsecurity || return 1
    info "Running: ./build rewrite_confs"
    ./build rewrite_confs || return 1
    cd - >/dev/null || true
    return 0
}

install_modsec_cpanel() {
    info "Backing up Apache config..."
    backup_path /etc/apache2/conf.d || return 1
    backup_path /etc/apache2/conf || true
    if command -v dnf >/dev/null 2>&1; then
        info "Running: dnf -y install ea-apache2-mod_security2"
        dnf -y install ea-apache2-mod_security2 || return 1
    elif command -v yum >/dev/null 2>&1; then
        info "Running: yum -y install ea-apache2-mod_security2"
        yum -y install ea-apache2-mod_security2 || return 1
    else
        warn "Neither dnf nor yum found."
        return 1
    fi
    return 0
}

ensure_modsec() {
    # LiteSpeed has ModSecurity built in; nothing to install.
    if [[ "$WEBSERVER" == "LiteSpeed" ]]; then
        info "LiteSpeed detected: ModSecurity support is built in, skipping module check."
        return 0
    fi

    alarm "ModSecurity is NOT enabled on this server (security2_module is not loaded)."
    alarm "Any SecRule would fail with: Invalid command 'SecRule'."
    reason "The rule can only work if ModSecurity is installed and loaded. Installing it now, with a backup first, lets the rule actually protect the hosted websites."
    if [[ "$PANEL" == "directadmin" ]]; then
        info "Install method: CustomBuild (modsecurity=yes, ruleset stays as currently set in options.conf)."
    else
        info "Install method: ea-apache2-mod_security2 package."
    fi

    if ! ask "Install ModSecurity now?"; then
        SKIPPED+=("ModSecurity installation (rule cannot be applied without it)")
        return 1
    fi

    local rc=0
    if [[ "$PANEL" == "directadmin" ]]; then
        install_modsec_directadmin || rc=1
    else
        install_modsec_cpanel || rc=1
    fi

    if [[ "$rc" -ne 0 ]]; then
        warn "ModSecurity installation failed. Backups are in ${BACKUP_DIR}"
        FAILED+=("ModSecurity installation")
        return 1
    fi

    if ! modsec_loaded; then
        warn "Installation finished but security2_module is still not loaded."
        FAILED+=("ModSecurity installation (module not loaded afterwards)")
        return 1
    fi

    ok "ModSecurity installed and loaded."
    DONE+=("ModSecurity module installed")
    RESTART_WEB=1
    return 0
}

# =====================================================
# ModSecurity rule (both panels)
# =====================================================
modsec_rollback() {
    warn "Restoring ModSecurity files from backup..."
    if [[ "$USE_INCLUDE" -eq 1 && -n "$MODSEC_INCLUDE_FILE" && -f "${BACKUP_DIR}${MODSEC_INCLUDE_FILE}" ]]; then
        cp -af "${BACKUP_DIR}${MODSEC_INCLUDE_FILE}" "$MODSEC_INCLUDE_FILE"
    fi
    if [[ "$RULE_EXISTED" -eq 1 ]]; then
        [[ -f "${BACKUP_DIR}${RULE_FILE}" ]] && cp -af "${BACKUP_DIR}${RULE_FILE}" "$RULE_FILE"
    else
        rm -f "$RULE_FILE"
    fi
}

step_modsec() {
    header "Install ModSecurity rule (php_session_upload_progress)"

    if ! detect_web; then
        warn "No active web server found."
        FAILED+=("ModSecurity (no web server)"); return
    fi
    info "Web server: ${WEBSERVER} (${SERVICE})"

    # Decide where the rule lives and whether an Include line is needed
    local include_file=""
    USE_INCLUDE=1
    if [[ "$PANEL" == "cpanel" ]]; then
        include_file="/etc/apache2/conf.d/modsec/modsec2.user.conf"
    else
        include_file="/etc/httpd/conf/extra/httpd-includes.conf"
        # DirectAdmin's own modsecurity config already includes /etc/modsecurity.d/*.conf
        if grep -qs '/etc/modsecurity.d/\*\.conf' /etc/httpd/conf/extra/httpd-modsecurity.conf 2>/dev/null; then
            RULE_DIR="/etc/modsecurity.d"
            RULE_FILE="${RULE_DIR}/infraguard.conf"
            USE_INCLUDE=0
        fi
    fi
    [[ "$USE_INCLUDE" -eq 1 ]] && MODSEC_INCLUDE_FILE="$include_file"
    info "Rule file: ${RULE_FILE}"

    # ---- Already applied? (module + rule file + include) ----
    local module_ok=0 rule_ok=0 include_ok=1
    if [[ "$WEBSERVER" == "LiteSpeed" ]] || modsec_loaded; then module_ok=1; fi
    grep -qs "id:${RULE_ID}" "$RULE_FILE" 2>/dev/null && rule_ok=1
    if [[ "$USE_INCLUDE" -eq 1 ]]; then
        grep -Fqs "${RULE_DIR}/*.conf" "$include_file" 2>/dev/null || include_ok=0
    fi
    if [[ "$module_ok" -eq 1 && "$rule_ok" -eq 1 && "$include_ok" -eq 1 ]]; then
        ok "Already done: ModSecurity is loaded and rule ${RULE_ID} is in place (${RULE_FILE})."
        ALREADY+=("ModSecurity rule ${RULE_ID} already installed in ${RULE_FILE}")
        SUGGEST_WEB=1
        return
    fi

    reason "This protects the hosted websites: requests with the php_session_upload_progress field in multipart uploads are blocked with 403, so the related PHP bug cannot be exploited against customer sites."
    if ! ask "Install the ModSecurity rule?"; then
        SKIPPED+=("ModSecurity rule"); return
    fi

    # Make sure ModSecurity exists before touching any rule files
    if [[ "$module_ok" -eq 0 ]]; then
        if ! ensure_modsec; then
            SKIPPED+=("ModSecurity rule (ModSecurity not available)")
            return
        fi
    fi

    if [[ "$USE_INCLUDE" -eq 1 ]]; then
        info "Include file: ${include_file}"
        if [[ ! -f "$include_file" ]]; then
            warn "Expected file not found: ${include_file}"
            FAILED+=("ModSecurity (include file missing)"); return
        fi
    fi

    # Duplicate ID check (ignores only the exact rule file we manage)
    local dups
    dups="$(grep -Rns --include='*.conf' --include='*.rules' \
        --exclude='*.bak.*' \
        "id:${RULE_ID}" /etc/httpd/conf /etc/apache2/conf.d /etc/modsecurity.d /etc/custom_modsecurity.d \
        /usr/local/directadmin/data/admin /usr/local/directadmin/data/users \
        2>/dev/null | grep -v "^${RULE_FILE}:" || true)"
    if [[ -n "$dups" ]]; then
        printf '%s\n' "$dups"
        warn "Rule ID ${RULE_ID} already exists elsewhere. Resolve duplicates first."
        FAILED+=("ModSecurity (duplicate rule ID)"); return
    fi

    if [[ -f "$RULE_FILE" ]]; then RULE_EXISTED=1; else RULE_EXISTED=0; fi

    info "Backing up files before changes..."
    if [[ "$USE_INCLUDE" -eq 1 ]] && ! backup_path "$include_file"; then
        warn "Backup failed. No changes made."
        FAILED+=("ModSecurity (backup failed)"); return
    fi
    if [[ "$RULE_EXISTED" -eq 1 ]] && ! backup_path "$RULE_FILE"; then
        warn "Backup failed. No changes made."
        FAILED+=("ModSecurity (backup failed)"); return
    fi

    mkdir -p "$RULE_DIR" && chmod 0755 "$RULE_DIR"

    if ! grep -q "id:${RULE_ID}" "$RULE_FILE" 2>/dev/null; then
        cat >> "$RULE_FILE" <<'RULES'

SecRule REQUEST_HEADERS:Content-Type "@contains multipart/form-data" "id:501500,phase:2,t:none,t:lowercase,chain,deny,status:403,log,auditlog,tag:'InfraGuard',msg:'InfraGuard - PHP session upload progress field blocked'"
SecRule ARGS_POST_NAMES|FILES_NAMES "@streq php_session_upload_progress" "t:none,t:lowercase"
RULES
    fi
    chmod 0644 "$RULE_FILE"

    if [[ "$USE_INCLUDE" -eq 1 ]] && ! grep -Fq "${RULE_DIR}/*.conf" "$include_file"; then
        printf '\nIncludeOptional %s/*.conf\n' "$RULE_DIR" >> "$include_file"
    fi

    if ! get_test_cmd; then
        modsec_rollback
        warn "No Apache-compatible config test tool found."
        FAILED+=("ModSecurity (cannot test config)"); return
    fi

    info "Testing configuration..."
    if ! "${TEST_CMD[@]}"; then
        modsec_rollback
        warn "Config test failed. Files restored."
        FAILED+=("ModSecurity (config test failed)"); return
    fi

    DONE+=("ModSecurity rule ${RULE_ID} installed in ${RULE_FILE}")
    RESTART_WEB=1
}

# ---------- Run steps ----------
if [[ "$PANEL" == "cpanel" ]]; then
    step_phpmyadmin
    step_roundcube
else
    step_csf_da_port
fi
step_modsec

# ---------- Restarts for changes we made ----------
header "Restarting services (for applied changes)"
ANY_RESTART=0

if [[ "$RESTART_CSF" -eq 1 ]]; then
    ANY_RESTART=1
    reason "CSF must be reloaded so the new port list takes effect."
    if csf -r; then ok "CSF restarted"; else warn "CSF restart failed"; FAILED+=("CSF restart"); fi
fi

if [[ "$RESTART_CPSRVD" -eq 1 ]]; then
    ANY_RESTART=1
    reason "cpsrvd must be restarted so the feature list and cPanel config changes take effect."
    if /scripts/restartsrv_cpsrvd; then ok "cpsrvd restarted"; else warn "cpsrvd restart failed"; FAILED+=("cpsrvd restart"); fi
fi

if [[ "$RESTART_DA" -eq 1 ]]; then
    ANY_RESTART=1
    reason "DirectAdmin is restarted to keep it consistent with the new firewall state."
    if systemctl restart directadmin; then ok "DirectAdmin restarted"; else warn "DirectAdmin restart failed"; FAILED+=("DirectAdmin restart"); fi
fi

if [[ "$RESTART_WEB" -eq 1 ]]; then
    ANY_RESTART=1
    reason "The web server (${SERVICE}) must be restarted to load the ModSecurity module/rule."
    if systemctl restart "$SERVICE"; then
        ok "${WEBSERVER} restarted"
    else
        warn "Restart of ${SERVICE} failed. Rolling back the ModSecurity rule..."
        modsec_rollback
        systemctl restart "$SERVICE" || true
        FAILED+=("${SERVICE} restart (ModSecurity rule rolled back)")
    fi
fi
[[ "$ANY_RESTART" -eq 0 ]] && info "Nothing was changed, no restart needed for applied changes."

# ---------- Precautionary restarts for already-applied steps ----------
# Skip services that were already restarted above
[[ "$RESTART_CSF"    -eq 1 ]] && SUGGEST_CSF=0
[[ "$RESTART_CPSRVD" -eq 1 ]] && SUGGEST_CPSRVD=0
[[ "$RESTART_DA"     -eq 1 ]] && SUGGEST_DA=0
[[ "$RESTART_WEB"    -eq 1 ]] && SUGGEST_WEB=0

if [[ $((SUGGEST_CSF + SUGGEST_CPSRVD + SUGGEST_DA + SUGGEST_WEB)) -gt 0 ]]; then
    header "Precautionary restart"
    echo "These steps were already applied earlier. Just to be safe, these services should be restarted:"
    [[ "$SUGGEST_CSF"    -eq 1 ]] && echo "  - CSF (csf -r)"
    [[ "$SUGGEST_CPSRVD" -eq 1 ]] && echo "  - cPanel (cpsrvd)"
    [[ "$SUGGEST_DA"     -eq 1 ]] && echo "  - DirectAdmin"
    [[ "$SUGGEST_WEB"    -eq 1 ]] && echo "  - Web server (${SERVICE})"

    if ask "Restart them now?"; then
        if [[ "$SUGGEST_CSF" -eq 1 ]]; then
            if csf -r; then ok "CSF restarted"; else warn "CSF restart failed"; FAILED+=("CSF restart"); fi
        fi
        if [[ "$SUGGEST_CPSRVD" -eq 1 ]]; then
            if /scripts/restartsrv_cpsrvd; then ok "cpsrvd restarted"; else warn "cpsrvd restart failed"; FAILED+=("cpsrvd restart"); fi
        fi
        if [[ "$SUGGEST_DA" -eq 1 ]]; then
            if systemctl restart directadmin; then ok "DirectAdmin restarted"; else warn "DirectAdmin restart failed"; FAILED+=("DirectAdmin restart"); fi
        fi
        if [[ "$SUGGEST_WEB" -eq 1 ]]; then
            info "Testing web server configuration before restart..."
            if get_test_cmd && "${TEST_CMD[@]}"; then
                if systemctl restart "$SERVICE"; then ok "${WEBSERVER} restarted"; else warn "${SERVICE} restart failed"; FAILED+=("${SERVICE} restart"); fi
            else
                warn "Config test failed or unavailable; web server was NOT restarted."
                FAILED+=("${SERVICE} restart skipped (config test failed)")
            fi
        fi
        DONE+=("Precautionary restart of services")
    else
        SKIPPED+=("Precautionary restart of services")
    fi
fi

# ---------- Summary ----------
header "Summary"
echo "Control panel: ${PANEL}"
echo "Backups:       ${BACKUP_DIR}"
echo
echo "Done:"
if [[ ${#DONE[@]} -eq 0 ]]; then echo "  - nothing"; else for i in "${DONE[@]}"; do echo "  - $i"; done; fi
echo
echo "Already done before this run:"
if [[ ${#ALREADY[@]} -eq 0 ]]; then echo "  - nothing"; else for i in "${ALREADY[@]}"; do echo "  - $i"; done; fi
echo
echo "Skipped:"
if [[ ${#SKIPPED[@]} -eq 0 ]]; then echo "  - nothing"; else for i in "${SKIPPED[@]}"; do echo "  - $i"; done; fi
if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo
    echo "Failed:"
    for i in "${FAILED[@]}"; do echo "  - $i"; done
fi
echo
echo "To restore any file, copy it back from ${BACKUP_DIR} (original path is preserved)."