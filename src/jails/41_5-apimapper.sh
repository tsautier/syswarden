syswarden_jail_apimapper() {
    # 1. Fail-Fast: Check against discovery engine results
    if [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
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

    # Abort if no log files match the wildcards yet to prevent Fail2ban crash
    if [[ "$HAS_LOGS" != "true" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected and verified. Enabling API Mapper Guard."

    # Create Filter for API Documentation and Schema discovery attempts
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-apimapper.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-apimapper.conf
[Definition]
# Detects reconnaissance on Swagger, OpenAPI, and GraphQL endpoints resulting in 403/404
failregex = ^<HOST> \S+ \S+ \[[^\]]+\] "(?:GET|POST|HEAD) [^"]*(?:/swagger-ui[^ "]*|/openapi\.json|/swagger\.json|/v[1-3]/api-docs|/api-docs[^ "]*|/graphiql|/graphql/schema) HTTP/[^"]*" (403|404)
ignoreregex = 
EOF
    fi

    # Write directly to jail.d using the sanitized space-separated log path
    # maxretry = 2: Allows for one accidental hit, bans on the second mapping attempt
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-apimapper.conf
[syswarden-apimapper]
enabled  = true
port     = http,https
filter   = syswarden-apimapper
logpath  = $CLEAN_LOGS
backend  = auto
maxretry = 2
bantime  = 48h
EOF
}
