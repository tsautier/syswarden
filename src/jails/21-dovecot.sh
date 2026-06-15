syswarden_jail_dovecot() {
    # 1. Fail-Fast: Verify native daemon execution at the absolute top
    if ! systemctl is-active --quiet dovecot 2>/dev/null; then
        return 0
    fi

    local DOVECOT_LOG=""

    # 2. Dynamic log path discovery based on OS distribution
    if [[ -f "/var/log/mail.log" ]]; then
        DOVECOT_LOG="/var/log/mail.log"
    elif [[ -f "/var/log/maillog" ]]; then
        DOVECOT_LOG="/var/log/maillog"
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$DOVECOT_LOG" ]]; then
        return 0
    fi

    log "INFO" "Dovecot daemon and logs detected. Enabling IMAP/POP3 Jail."

    # Filter for Dovecot Auth Failures (catches standard rip=IP format)
    if [[ ! -f "/etc/fail2ban/filter.d/dovecot.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/dovecot.conf
[Definition]
failregex = ^.*dovecot: .*(?:Authentication failure|Aborted login|auth failed).*rip=<HOST>,.*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-dovecot.conf
[syswarden-dovecot]
enabled  = true
port     = pop3,pop3s,imap,imaps,submission,4190,sieve
filter   = dovecot
logpath  = $DOVECOT_LOG
backend  = auto
maxretry = 5
bantime  = 24h
EOF
}
