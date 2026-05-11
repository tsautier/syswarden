syswarden_jail_modsec() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ "${SYSW_MODSEC_ACTIVE:-0}" -ne 1 ]] || [[ -z "${SYSW_MODSEC_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "ModSecurity WAF detected. Enabling Purple Team integration."

    # Create Filter for ModSecurity Access Denied events
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-modsec.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-modsec.conf
[Definition]
# Matches ModSecurity 4xx/5xx denials and pattern matches in web server error logs
failregex = ^.*\[(?:error|warn)\].*?\[client <HOST>(?::\d+)?\].*?ModSecurity: Access denied with code [45]\d\d.*$
            ^.*\[(?:error|warn)\].*?\[client <HOST>(?::\d+)?\].*?ModSecurity: Warning\. Pattern match.*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-modsec.conf
[syswarden-modsec]
enabled  = true
port     = http,https
filter   = syswarden-modsec
logpath  = $SYSW_MODSEC_LOGS
backend  = auto
maxretry = 3
findtime = 10m
bantime  = 24h
EOF
}
