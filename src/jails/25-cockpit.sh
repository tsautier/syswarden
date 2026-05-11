syswarden_jail_cockpit() {
    # 1. Fail-Fast: Verify native socket execution or config presence at the absolute top
    if ! systemctl is-active --quiet cockpit.socket 2>/dev/null && [[ ! -d "/etc/cockpit" ]]; then
        return 0
    fi

    local COCKPIT_LOG=""

    # 2. Dynamic log path discovery based on OS distribution
    if [[ -f "/var/log/secure" ]]; then
        COCKPIT_LOG="/var/log/secure" # RHEL/Alma/Rocky
    elif [[ -f "/var/log/auth.log" ]]; then
        COCKPIT_LOG="/var/log/auth.log" # Debian/Ubuntu
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$COCKPIT_LOG" ]]; then
        return 0
    fi

    log "INFO" "Cockpit Web Console detected. Enabling Cockpit Jail."

    if [[ ! -f "/etc/fail2ban/filter.d/cockpit-custom.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/cockpit-custom.conf
[Definition]
failregex = ^.*?cockpit-ws.*?(?:authentication failed|invalid user).*?from <HOST>.*$
ignoreregex = 
EOF
    fi

    # Utilise la variable globale SYSW_OS_BACKEND propagée par le moteur principal
    cat <<EOF >/etc/fail2ban/jail.d/cockpit.conf
[cockpit-custom]
enabled  = true
port     = 9090
filter   = cockpit-custom
logpath  = $COCKPIT_LOG
backend  = ${SYSW_OS_BACKEND:-auto}
maxretry = 3
bantime  = 24h
EOF
}
