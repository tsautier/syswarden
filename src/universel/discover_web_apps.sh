discover_web_apps() {
    log "INFO" "Discovering active Web Servers and underlying applications..."

    # Reset global state to prevent persistence across reloads
    export SYSW_RCE_LOGS=""
    export SYSW_HAS_DOLIBARR=false
    export SYSW_HAS_PRESTASHOP=false
    export SYSW_HAS_WORDPRESS=false
    export SYSW_HAS_DRUPAL=false
    export SYSW_HAS_NEXTCLOUD=false
    export SYSW_HAS_PHPMYADMIN=false
    export SYSW_HAS_LARAVEL=false

    local web_conf_dirs=""
    local raw_web_patterns=""

    # 1. Native detection of active Web Servers
    if command -v nginx >/dev/null 2>&1 && systemctl is-active --quiet nginx 2>/dev/null; then
        # Standard patterns for Nginx
        raw_web_patterns="/var/log/nginx/*access.log /var/log/nginx/*error.log"
        web_conf_dirs="/etc/nginx"
    fi

    if command -v apache2 >/dev/null 2>&1 && systemctl is-active --quiet apache2 2>/dev/null; then
        raw_web_patterns="${raw_web_patterns:+$raw_web_patterns }/var/log/apache2/*access.log /var/log/apache2/*error.log"
        web_conf_dirs="${web_conf_dirs:+$web_conf_dirs }/etc/apache2"
    elif command -v httpd >/dev/null 2>&1 && systemctl is-active --quiet httpd 2>/dev/null; then
        raw_web_patterns="${raw_web_patterns:+$raw_web_patterns }/var/log/httpd/*access.log /var/log/httpd/*error_log"
        web_conf_dirs="${web_conf_dirs:+$web_conf_dirs }/etc/httpd"
    fi

    # --- LOG ASSURANCE ENGINE (v0.32.5 - ShellCheck Compliance) ---
    local verified_patterns=""
    if [[ -n "$raw_web_patterns" ]]; then
        for pattern in $raw_web_patterns; do
            # SC2155 FIX: Declare and assign separately to avoid masking return values
            local log_dir base_name
            log_dir=$(dirname "$pattern")
            base_name=$(basename "$pattern" | sed 's/^\*//')

            if [[ -d "$log_dir" ]]; then
                # PURPLE TEAM FIX: Ensure at least one file exists to prevent Fail2ban crash
                # shellcheck disable=SC2086
                if ! ls $pattern >/dev/null 2>&1; then
                    touch "$log_dir/$base_name" 2>/dev/null || true
                fi
                verified_patterns="${verified_patterns:+$verified_patterns }$pattern"
            fi
        done
    fi
    # Export the space-separated patterns containing wildcards
    export SYSW_RCE_LOGS="${verified_patterns}"
    # ---------------------------------------------------------------

    # 2. Application Heuristic Discovery (Only if a Web Server runs)
    if [[ -n "$web_conf_dirs" ]]; then
        # Fast configuration parsing (Reverse lookup)
        grep -riEq 'dolibarr' $web_conf_dirs 2>/dev/null && SYSW_HAS_DOLIBARR=true || true
        grep -riEq 'prestashop' $web_conf_dirs 2>/dev/null && SYSW_HAS_PRESTASHOP=true || true
        grep -riEq 'wp-config|wordpress' $web_conf_dirs 2>/dev/null && SYSW_HAS_WORDPRESS=true || true
        grep -riEq 'drupal' $web_conf_dirs 2>/dev/null && SYSW_HAS_DRUPAL=true || true
        grep -riEq 'nextcloud' $web_conf_dirs 2>/dev/null && SYSW_HAS_NEXTCLOUD=true || true
        grep -riEq 'phpmyadmin' $web_conf_dirs 2>/dev/null && SYSW_HAS_PHPMYADMIN=true || true
        grep -riEq 'laravel|artisan' $web_conf_dirs 2>/dev/null && SYSW_HAS_LARAVEL=true || true

        # Shallow filesystem probing
        for root in /var/www /usr/share/nginx/html /opt; do
            if [[ -d "$root" ]]; then
                find "$root" -maxdepth 4 -type f -name "wp-config.php" 2>/dev/null | head -n 1 | grep -q . && SYSW_HAS_WORDPRESS=true || true
                find "$root" -maxdepth 4 -type f -name "artisan" 2>/dev/null | head -n 1 | grep -q . && SYSW_HAS_LARAVEL=true || true
                find "$root" -maxdepth 4 -type d -name "phpmyadmin" 2>/dev/null | head -n 1 | grep -q . && SYSW_HAS_PHPMYADMIN=true || true
                find "$root" -maxdepth 4 -type d -name "drupal" 2>/dev/null | head -n 1 | grep -q . && SYSW_HAS_DRUPAL=true || true
                find "$root" -maxdepth 4 -type f -name "status.php" -path "*/nextcloud/*" 2>/dev/null | head -n 1 | grep -q . && SYSW_HAS_NEXTCLOUD=true || true
            fi
        done
    fi

    return 0
}
