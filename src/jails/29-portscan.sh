syswarden_jail_portscan() {
    local FIREWALL_LOG=""

    # 1. Dynamic log path discovery for Kernel/Netfilter messages
    if [[ -f "/var/log/kern-firewall.log" ]]; then
        FIREWALL_LOG="/var/log/kern-firewall.log"
    elif [[ -f "/var/log/kern.log" ]]; then
        FIREWALL_LOG="/var/log/kern.log"
    elif [[ -f "/var/log/messages" ]]; then
        FIREWALL_LOG="/var/log/messages"
    elif [[ -f "/var/log/syslog" ]]; then
        FIREWALL_LOG="/var/log/syslog"
    fi

    # 2. Fail-Fast: Ensure kernel logs exist to prevent Fail2ban crash
    if [[ -z "$FIREWALL_LOG" ]]; then
        return 0
    fi

    log "INFO" "Kernel logs detected. Enabling Port Scanner Guard."

    # Create Filter for SysWarden-BLOCK iptables/nftables prefix
    if [[ ! -f "/etc/fail2ban/filter.d/syswarden-portscan.conf" ]]; then
        cat <<'EOF' >/etc/fail2ban/filter.d/syswarden-portscan.conf
[INCLUDES]
before = common.conf

[Definition]
failregex = ^%(__prefix_line)s(?:kernel:\s+)?(?:\[\s*\d+\.\d+\]\s+)?\[SysWarden-BLOCK\].*?SRC=<HOST> 
ignoreregex = 
EOF
    fi

    # Write directly to jail.d for clean segmentation
    cat <<EOF >/etc/fail2ban/jail.d/syswarden-portscan.conf
[syswarden-portscan]
enabled  = true
port     = 0:65535
filter   = syswarden-portscan
logpath  = $FIREWALL_LOG
backend  = ${SYSW_OS_BACKEND:-auto}
maxretry = 3
findtime = 10m
bantime  = 24h
EOF
}
