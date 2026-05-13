syswarden_jail_ssrf() {
    # 1. Fail-Fast: Check against discovery engine results (Zero I/O overhead)
    if [[ -z "${SYSW_RCE_LOGS:-}" ]]; then
        return 0
    fi

    log "INFO" "Web access logs detected. Enabling SSRF & Cloud Metadata Guard."

    # Create Filter for SSRF & Cloud Metadata Exfiltration attempts
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-ssrf.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-ssrf.conf
[Definition]
# Detects requests targeting Cloud Metadata IP (169.254.169.254) and specific provider endpoints
failregex = ^<HOST> \S+ \S+ \[[^\]]*\] "(?:GET|POST|HEAD|PUT) .*(?:169\.254\.169\.254|2852039166|0xa9fea9fe|/metadata/instance|/metadata/identity|latest/meta-data|metadata\.google\.internal|/v1/user-data|/metadata/v1|100\.100\.100\.200|192\.0\.0\.192).* HTTP/.*" \d{3} .*$
ignoreregex = 
EOF
    fi

    # Write directly to jail.d
    # maxretry = 1: Critical alert, instant ban for 48h to protect infrastructure credentials
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-ssrf.conf
[syswarden-ssrf]
enabled  = true
port     = http,https
filter   = syswarden-ssrf
logpath  = $SYSW_RCE_LOGS
backend  = auto
maxretry = 1
bantime  = 48h
EOF
}
