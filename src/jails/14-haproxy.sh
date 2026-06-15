syswarden_jail_haproxy() {
    # 1. Fail-Fast: Verify native daemon execution at the absolute top
    if ! systemctl is-active --quiet haproxy 2>/dev/null; then
        return 0
    fi

    # 2. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ ! -f "/var/log/haproxy.log" ]]; then
        return 0
    fi

    log "INFO" "HAProxy daemon and logs detected. Enabling HAProxy Jail."

    # Create Filter for HTTP Errors (403 Forbidden, 404 Scan, 429 RateLimit)
    if [[ ! -f "/etc/fail2ban/filter.d/haproxy-http-auth.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/haproxy-http-auth.conf
[Definition]
failregex = ^.*? <HOST>:\d+ .*? (?:400|403|404|429) .*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-haproxy.conf
[syswarden-haproxy-http-auth]
enabled  = true
port     = http,https,8080
filter   = haproxy-http-auth
logpath  = /var/log/haproxy.log
backend  = auto
maxretry = 5
bantime  = 24h
EOF
}
