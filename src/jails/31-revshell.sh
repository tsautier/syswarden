syswarden_jail_revshell() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling Reverse Shell & RCE Guard."

    # Create Filter for RCE & Reverse Shell patterns
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-revshell.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-revshell.conf
[Definition]
# Detects common RCE patterns, shell invocations, and encoded payloads in URI/Requests
failregex = ^<HOST> \S+ \S+ \[[^\]]*\] "(?:GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS) [^"]*?(?:/bin/bash|\x252Fbin\x252Fbash|/bin/sh|\x252Fbin\x252Fsh|nc(?:\s+|\x2520|\x2509|\+)+(?:-e|-c)|(?:curl|wget)(?:\s+|\x2520|\x2509|\+)+(?:-q|-s|-O|http)|(?:python|perl|ruby|php|node|lua|awk)(?:\s+|\x2520|\x2509|\+)+-(?:c|e|r)|(?:\x253B|;|\x257C|\||`|\x2560|\$|\x2524)(?:\s+|\x2520|\x2509|\+)*(?:bash|sh|nc|curl|wget|chmod)).*?" .*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d
    # maxretry = 1 for immediate banning on RCE detection
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-revshell.conf
[syswarden-revshell]
enabled  = true
port     = http,https
filter   = syswarden-revshell
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 1
findtime = 3600
bantime  = 24h
EOF
}
