syswarden_jail_sendmail() {
    # 1. Fail-Fast: Verify native daemon execution at the absolute top
    if ! systemctl is-active --quiet sendmail 2>/dev/null; then
        return 0
    fi

    local SM_LOG=""

    # 2. Dynamic log path discovery based on OS distribution
    if [[ -f "/var/log/mail.log" ]]; then
        SM_LOG="/var/log/mail.log" # Debian/Ubuntu
    elif [[ -f "/var/log/maillog" ]]; then
        SM_LOG="/var/log/maillog" # RHEL/Alma/Rocky
    fi

    # 3. Fail-Fast: Ensure logs exist to prevent Fail2ban crash on startup
    if [[ -z "$SM_LOG" ]]; then
        return 0
    fi

    log "INFO" "Sendmail daemon and logs detected. Enabling Sendmail Jails."

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/etc/fail2ban/jail.d/sendmail.conf
[sendmail-auth]
enabled  = true
port     = smtp,465,submission
logpath  = $SM_LOG
backend  = auto
maxretry = 3
bantime  = 24h

[sendmail-reject]
enabled  = true
port     = smtp,465,submission
logpath  = $SM_LOG
backend  = auto
maxretry = 5
bantime  = 24h
EOF
}
