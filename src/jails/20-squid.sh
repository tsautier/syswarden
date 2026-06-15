syswarden_jail_squid() {
    # 1. Fail-Fast: Verify native daemon execution at the absolute top
    if ! systemctl is-active --quiet squid 2>/dev/null; then
        return 0
    fi

    # 2. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ ! -f "/var/log/squid/access.log" ]]; then
        return 0
    fi

    log "INFO" "Squid Proxy daemon and logs detected. Enabling Squid Jail."

    # Create Filter for Proxy Abuse (TCP_DENIED / 403 / 407)
    if [[ ! -f "/etc/fail2ban/filter.d/squid.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/squid.conf
[Definition]
failregex = ^\s*<HOST> .*(?:TCP_DENIED|ERR_ACCESS_DENIED).*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-squid.conf
[syswarden-squid]
enabled  = true
port     = 3128,8080
filter   = squid
logpath  = /var/log/squid/access.log
backend  = auto
maxretry = 5
bantime  = 24h
EOF
}
