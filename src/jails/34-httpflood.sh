syswarden_jail_httpflood() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling Layer 7 Anti-DDoS Guard."

    # Create Filter for HTTP Request Rate Limiting
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-httpflood.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-httpflood.conf
[Definition]
# Generic request match for high-frequency counting
failregex = ^<HOST> \S+ \S+ \[
ignoreregex = 
EOF
    fi

    # Write directly to jail.d
    # High maxretry paired with very short findtime to catch flooding bursts
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-httpflood.conf
[syswarden-httpflood]
enabled  = true
port     = http,https
filter   = syswarden-httpflood
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 300
findtime = 5
bantime  = 24h
EOF
}
