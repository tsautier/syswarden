syswarden_jail_apache() {
    # 1. Fail-Fast: Verify native daemon execution (Debian & RHEL) at the absolute top
    if ! systemctl is-active --quiet apache2 2>/dev/null && ! systemctl is-active --quiet httpd 2>/dev/null; then
        return 0
    fi

    local APACHE_LOG=""
    local APACHE_ACCESS=""

    # 2. Dynamic log path discovery based on OS distribution
    if [[ -f "/var/log/apache2/error.log" ]] && [[ -f "/var/log/apache2/access.log" ]]; then
        APACHE_LOG="/var/log/apache2/error.log"
        APACHE_ACCESS="/var/log/apache2/access.log"
    elif [[ -f "/var/log/httpd/error_log" ]] && [[ -f "/var/log/httpd/access_log" ]]; then
        APACHE_LOG="/var/log/httpd/error_log"
        APACHE_ACCESS="/var/log/httpd/access_log"
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$APACHE_LOG" ]] || [[ -z "$APACHE_ACCESS" ]]; then
        return 0
    fi

    log "INFO" "Apache daemon and logs detected. Enabling Apache Jails."

    # Create Filter for 404/403 scanners (Apache specific)
    # [DEVSECOPS FIX] Enforced 'syswarden-' namespace for custom heuristic filter
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-apache-scanner.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-apache-scanner.conf
[Definition]
# Included HTTP 30x redirects and dynamic [A-Z]+ verbs to catch all evasive vulnerability scanners
failregex = ^<HOST> \S+ \S+ (?:\[[^\]]*\]\s+)?"[A-Z]+ [^"]*?" (?:30[1278]|400|401|403|404|405)
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-apache.conf
[syswarden-apache-auth]
enabled  = true
port     = http,https
filter   = apache-auth
logpath  = $APACHE_LOG
backend  = auto
maxretry = 5
bantime  = 24h

[syswarden-apache-badbots]
enabled  = true
port     = http,https
filter   = apache-badbots
logpath  = $APACHE_ACCESS
backend  = auto
maxretry = 2
bantime  = 24h

[syswarden-apache-noscript]
enabled  = true
port     = http,https
filter   = apache-noscript
logpath  = $APACHE_LOG
backend  = auto
maxretry = 5
bantime  = 24h

[syswarden-apache-overflows]
enabled  = true
port     = http,https
filter   = apache-overflows
logpath  = $APACHE_LOG
backend  = auto
maxretry = 2
bantime  = 24h

[syswarden-apache-scanner]
enabled  = true
port     = http,https
filter   = syswarden-apache-scanner
logpath  = $APACHE_ACCESS
backend  = auto
maxretry = 15
bantime  = 24h
EOF
}
