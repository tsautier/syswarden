syswarden_jail_secretshunter() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling Stealth Secrets Hunter Guard."

    # Create Filter for Sensitive Files and Secrets Enumeration
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-secretshunter.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-secretshunter.conf
[Definition]
# Detects access attempts to critical configuration files, private keys, and DB backups
failregex = ^<HOST> \S+ \S+ \[.*?\] "(?:GET|POST|HEAD|PUT) .*(?:/\.env[^ ]*|/\.git/?.*|/\.aws/?.*|/\.ssh/?.*|/id_rsa[^ ]*|/id_ed25519[^ ]*|/[^ ]*\.(?:sql|bak|swp|db|sqlite3?)(?:\.gz|\.zip)?|/docker-compose\.ya?ml|/wp-config\.php\.(?:bak|save|old|txt|zip)) HTTP/.*" \d{3} .*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d
    # maxretry = 1: Instant ban for any attempt to access restricted metadata/secrets
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-secretshunter.conf
[syswarden-secretshunter]
enabled  = true
port     = http,https
filter   = syswarden-secretshunter
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
}
