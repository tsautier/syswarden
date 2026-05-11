syswarden_jail_drupal() {
    # 1. Fail-Fast: Surgical check against discovery engine state
    if [[ "${SYSW_HAS_DRUPAL:-false}" != "true" ]] || [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    # 2. Strict Log Sanitization: Remove commas and verify physical existence
    local CLEAN_LOGS="${SYSW_RCE_LOGS//,/ }"
    local HAS_LOGS=false

    for log_pattern in $CLEAN_LOGS; do
        # Evaluate wildcard safely without triggering set -e on failure
        if ls $log_pattern >/dev/null 2>&1; then
            HAS_LOGS=true
            break
        fi
    done

    # Abort if no log files match the wildcards yet
    if [[ "$HAS_LOGS" != "true" ]]; then
        return 0
    fi

    log "INFO" "Drupal CMS detected and logs verified. Enabling specific protections."

    # Create Filter for Drupal Authentication Failures
    if [[ ! -f "/etc/fail2ban/filter.d/drupal-auth.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/drupal-auth.conf
[Definition]
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "POST [^"]*?(?:/user/login|\?q=user/login)[^"]*?" 200
ignoreregex = 
EOF
    fi

    # Write directly to jail.d using the sanitized space-separated log path
    cat <<EOF >/etc/fail2ban/jail.d/drupal.conf
[drupal-auth]
enabled  = true
port     = http,https
filter   = drupal-auth
logpath  = $CLEAN_LOGS
backend  = auto
maxretry = 3
bantime  = 24h
EOF
}
