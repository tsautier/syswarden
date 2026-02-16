#!/bin/bash

# --- ALPINE LINUX SAFETY FIRST ---
if [ -z "$BASH_VERSION" ]; then
    echo "ERROR: This script requires Bash."
    echo "Please install it first by running: apk add bash"
    echo "Then re-run the script with: bash $0"
    exit 1
fi

set -euo pipefail
IFS=$'\n\t'

# --- COLORS & FORMATTING ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- CONFIGURATION CONSTANTS ---
LOG_FILE="/var/log/syswarden-install.log"
CONF_FILE="/etc/syswarden.conf"
SET_NAME="syswarden_blacklist"
TMP_DIR=$(mktemp -d)

# --- LIST URLS ---
declare -A URLS_STANDARD
URLS_STANDARD[GitHub]="https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_data-shield_ipv4_blocklist.txt"
URLS_STANDARD[GitLab]="https://gitlab.com/duggytuxy/data-shield-ipv4-blocklist/-/raw/main/prod_data-shield_ipv4_blocklist.txt"
URLS_STANDARD[Bitbucket]="https://bitbucket.org/duggytuxy/data-shield-ipv4-blocklist/raw/HEAD/prod_data-shield_ipv4_blocklist.txt"
URLS_STANDARD[Codeberg]="https://codeberg.org/duggytuxy21/Data-Shield_IPv4_Blocklist/raw/branch/main/prod_data-shield_ipv4_blocklist.txt"

declare -A URLS_CRITICAL
URLS_CRITICAL[GitHub]="https://raw.githubusercontent.com/duggytuxy/Data-Shield_IPv4_Blocklist/refs/heads/main/prod_critical_data-shield_ipv4_blocklist.txt"
URLS_CRITICAL[GitLab]="https://gitlab.com/duggytuxy/data-shield-ipv4-blocklist/-/raw/main/prod_critical_data-shield_ipv4_blocklist.txt"
URLS_CRITICAL[Bitbucket]="https://bitbucket.org/duggytuxy/data-shield-ipv4-blocklist/raw/HEAD/prod_critical_data-shield_ipv4_blocklist.txt"
URLS_CRITICAL[Codeberg]="https://codeberg.org/duggytuxy21/Data-Shield_IPv4_Blocklist/raw/branch/main/prod_critical_data-shield_ipv4_blocklist.txt"

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
       echo -e "${RED}ERROR: This script must be run as root.${NC}"
       exit 1
    fi
}

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

detect_os_backend() {
    log "INFO" "Detecting Operating System and Firewall Backend..."
    
    if [ -f /etc/alpine-release ]; then
        OS="Alpine Linux"
        OS_ID="alpine"
    else
        log "ERROR" "This specific script is designed ONLY for Alpine Linux."
        exit 1
    fi

    # Logic to select the best firewall for Alpine
    if command -v nft >/dev/null 2>&1 || apk info -e nftables >/dev/null 2>&1; then
        FIREWALL_BACKEND="nftables"
    else
        FIREWALL_BACKEND="ipset" # Fallback Iptables
    fi

    log "INFO" "OS: $OS"
    log "INFO" "Detected Firewall Backend: $FIREWALL_BACKEND"
}

install_dependencies() {
    log "INFO" "Updating apk repositories and installing dependencies..."
    apk update -q

    local deps="curl python3 py3-requests ipset fail2ban bash coreutils grep gawk sed procps logrotate ncurses"
    
    if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
        deps="$deps nftables"
    else
        deps="$deps iptables ip6tables"
    fi

    for pkg in $deps; do
        if ! apk info -e "$pkg" >/dev/null 2>&1; then
            log "INFO" "Installing package: $pkg"
            apk add -q "$pkg"
        fi
    done

    # Ensure OpenRC services are available
    if ! command -v rc-update >/dev/null; then
        log "ERROR" "OpenRC is missing. This script requires a standard Alpine setup."
        exit 1
    fi

    log "INFO" "All dependencies check complete."
}

define_ssh_port() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        if [[ -z "${SSH_PORT:-}" ]]; then SSH_PORT=22; fi
        log "INFO" "Update Mode: Preserving SSH Port $SSH_PORT"
        return
    fi

    echo -e "\n${BLUE}=== Step: SSH Configuration ===${NC}"
    read -p "Please enter your current SSH Port [Default: 22]: " input_port
    SSH_PORT=${input_port:-22}

    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
        log "WARN" "Invalid port detected. Defaulting to 22."
        SSH_PORT=22
    fi

    echo "SSH_PORT='$SSH_PORT'" >> "$CONF_FILE"
    log "INFO" "SSH Port configured as: $SSH_PORT"
}

# ==============================================================================
# CORE LOGIC
# ==============================================================================

select_list_type() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        source "$CONF_FILE"
        log "INFO" "Update Mode: Loaded configuration (Type: $LIST_TYPE)"
        return
    fi

    echo -e "\n${BLUE}=== Step 1: Select Blocklist Type ===${NC}"
    echo "1) Standard List (~85,000 IPs) - Recommended for Web Servers"
    echo "2) Critical List (~100,000 IPs) - Recommended for High Security"
    echo "3) Custom List"
    read -p "Enter choice [1/2/3]: " choice

    case "$choice" in
        1) LIST_TYPE="Standard";;
        2) LIST_TYPE="Critical";;
        3) 
           LIST_TYPE="Custom"
           read -p "Enter the full URL: " CUSTOM_URL
           ;;
        *) log "ERROR" "Invalid choice. Exiting."; exit 1;;
    esac
    
    echo "LIST_TYPE='$LIST_TYPE'" > "$CONF_FILE"
    if [[ -n "${CUSTOM_URL:-}" ]]; then echo "CUSTOM_URL='$CUSTOM_URL'" >> "$CONF_FILE"; fi
    log "INFO" "User selected: $LIST_TYPE Blocklist"
}

measure_latency() {
    local url="$1"
    local time_sec
    time_sec=$(curl -o /dev/null -s -w '%{time_connect}\n' --connect-timeout 2 "$url" || echo "error")
    
    if [[ "$time_sec" == "error" ]] || [[ -z "$time_sec" ]]; then
        echo "9999"
    else
        echo "$time_sec" | awk '{print int($1 * 1000)}' 2>/dev/null || echo "9999"
    fi
}

select_mirror() {
    if [[ "${1:-}" == "update" ]] && [[ -f "$CONF_FILE" ]]; then
        source "$CONF_FILE"
        log "INFO" "Update Mode: keeping mirror $SELECTED_URL"
        return
    fi

    if [[ "$LIST_TYPE" == "Custom" ]]; then
        SELECTED_URL="$CUSTOM_URL"
        echo "SELECTED_URL='$SELECTED_URL'" >> "$CONF_FILE"
        return
    fi

    echo -e "\n${BLUE}=== Step 2: Selecting Fastest Mirror ===${NC}"
    log "INFO" "Benchmarking mirrors..."

    declare -n URL_MAP
    if [[ "$LIST_TYPE" == "Standard" ]]; then URL_MAP=URLS_STANDARD; else URL_MAP=URLS_CRITICAL; fi

    local fastest_time=10000
    local fastest_url=""
    local valid_mirror_found=false

    for name in "${!URL_MAP[@]}"; do
        url="${URL_MAP[$name]}"
        echo -n "Connecting to $name... "
        time=$(measure_latency "$url")
        
        if [[ "$time" -eq 9999 ]]; then
             echo "FAIL"
        else
             echo "${time} ms"
             if (( time < fastest_time )); then
                fastest_time=$time
                fastest_url=$url
                valid_mirror_found=true
             fi
        fi
    done

    if [[ "$valid_mirror_found" == "false" ]]; then
        SELECTED_URL="${URL_MAP[Codeberg]}"
    else
        SELECTED_URL="$fastest_url"
    fi

    echo "SELECTED_URL='$SELECTED_URL'" >> "$CONF_FILE"
}

download_list() {
    echo -e "\n${BLUE}=== Step 3: Downloading Blocklist ===${NC}"
    log "INFO" "Fetching list from $SELECTED_URL..."
    
    local output_file="$TMP_DIR/blocklist.txt"
    if curl -sS -L --retry 3 --connect-timeout 10 "$SELECTED_URL" -o "$output_file"; then
        tr -d '\r' < "$output_file" | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$' > "$TMP_DIR/clean_list.txt"
        FINAL_LIST="$TMP_DIR/clean_list.txt"
        log "INFO" "Download success."
    else
        log "ERROR" "Failed to download blocklist."
        exit 1
    fi
}

apply_firewall_rules() {
    echo -e "\n${BLUE}=== Step 4: Applying Firewall Rules ($FIREWALL_BACKEND) ===${NC}"
    
    if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
        log "INFO" "Configuring Nftables Set..."
        rc-update add nftables default >/dev/null 2>&1 || true
        rc-service nftables start >/dev/null 2>&1 || true

        cat <<EOF > "$TMP_DIR/syswarden.nft"
table inet syswarden_table {
    set $SET_NAME {
        type ipv4_addr
        flags interval
        auto-merge
        elements = {
$(awk '{print $1 ","}' "$FINAL_LIST")
        }
    }
    chain input {
        type filter hook input priority filter - 10; policy accept;
        ip saddr @$SET_NAME log prefix "[SysWarden-BLOCK] " flags all drop
        tcp dport { 23, 445, 1433, 3389, 5900 } log prefix "[SysWarden-BLOCK] " flags all drop
    }
}
EOF
        nft -f "$TMP_DIR/syswarden.nft"
        nft list ruleset > /etc/nftables.nft

    else
        # Fallback IPSET / IPTABLES
        rc-update add iptables default >/dev/null 2>&1 || true
        
        ipset create "${SET_NAME}_tmp" hash:net maxelem 200000 -exist
        sed "s/^/add ${SET_NAME}_tmp /" "$FINAL_LIST" | ipset restore
        ipset create "$SET_NAME" hash:net maxelem 200000 -exist
        ipset swap "${SET_NAME}_tmp" "$SET_NAME"
        ipset destroy "${SET_NAME}_tmp"
        
        if ! iptables -C INPUT -m set --match-set "$SET_NAME" src -j DROP 2>/dev/null; then
            iptables -I INPUT 1 -m set --match-set "$SET_NAME" src -j DROP
            iptables -I INPUT 1 -m set --match-set "$SET_NAME" src -j LOG --log-prefix "[SysWarden-BLOCK] "
            iptables -I INPUT 2 -p tcp -m multiport --dports 23,445,1433,3389,5900 -j DROP
            iptables -I INPUT 2 -p tcp -m multiport --dports 23,445,1433,3389,5900 -j LOG --log-prefix "[SysWarden-BLOCK] "
            
            /etc/init.d/iptables save >/dev/null 2>&1 || true
        fi
    fi
}

configure_fail2ban() {
    if command -v fail2ban-client >/dev/null; then
        log "INFO" "Generating Fail2ban configuration (Alpine Universal Mode)..."
		
        if [[ -f /etc/fail2ban/jail.local ]] && [[ ! -f /etc/fail2ban/jail.local.bak ]]; then
            log "INFO" "Creating backup of existing jail.local"
            cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak
        fi

        # Alpine uses syslog or local files, NOT systemd.
        cat <<EOF > /etc/fail2ban/fail2ban.local
[Definition]
logtarget = /var/log/fail2ban.log
EOF

        # Backend MUST be auto or polling for Alpine.
        cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 4h
bantime.increment = true
findtime = 10m
maxretry = 3
ignoreip = 127.0.0.1/8 ::1
backend = auto
banaction = iptables-multiport

# --- SSH Protection ---
[sshd]
enabled = true
mode = aggressive
port = $SSH_PORT
logpath = /var/log/messages
backend = auto
EOF

        # Enable OpenRC service
        rc-update add fail2ban default >/dev/null 2>&1 || true
        rc-service fail2ban restart >/dev/null 2>&1 || true
    fi 
}

setup_abuse_reporting() {
    echo -e "\n${BLUE}=== Step 7: AbuseIPDB Reporting Setup ===${NC}"
    echo "Would you like to automatically report blocked IPs to AbuseIPDB?"
    read -p "Enable AbuseIPDB reporting? (y/N): " response

    if [[ "$response" =~ ^[Yy]$ ]]; then
        read -p "Enter your AbuseIPDB API Key: " USER_API_KEY
        
        if [[ -z "$USER_API_KEY" ]]; then
            log "ERROR" "No API Key provided. Skipping reporting setup."
            return
        fi

        echo ""
        read -p "Report Fail2ban Bans (SSH/Web brute-force)? [Y/n]: " REPORT_F2B
        REPORT_F2B=${REPORT_F2B:-y}

        echo ""
        read -p "Report Firewall Drops (Port Scans/Blacklist)? [Y/n]: " REPORT_FW
        REPORT_FW=${REPORT_FW:-y}

        if [[ "$REPORT_F2B" =~ ^[Nn]$ ]] && [[ "$REPORT_FW" =~ ^[Nn]$ ]]; then
            log "INFO" "Both reporting options declined. Skipping."
            return
        fi

        log "INFO" "Configuring Unified SysWarden Reporter for Alpine..."
        
        cat <<'EOF' > /usr/local/bin/syswarden_reporter.py
#!/usr/bin/env python3
import subprocess
import select
import re
import requests
import time
import os

# --- CONFIGURATION ---
API_KEY = "PLACEHOLDER_KEY"
REPORT_INTERVAL = 900  # 15 minutes
ENABLE_F2B = PLACEHOLDER_F2B
ENABLE_FW = PLACEHOLDER_FW

# --- DEFINITIONS ---
reported_cache = {}

def send_report(ip, categories, comment):
    current_time = time.time()
    if ip in reported_cache:
        if current_time - reported_cache[ip] < REPORT_INTERVAL:
            return 
    
    url = 'https://api.abuseipdb.com/api/v2/report'
    headers = {'Key': API_KEY, 'Accept': 'application/json'}
    params = {'ip': ip, 'categories': categories, 'comment': comment}

    try:
        response = requests.post(url, params=params, headers=headers)
        if response.status_code == 200:
            print(f"[SUCCESS] Reported {ip} -> Cats [{categories}]")
            reported_cache[ip] = current_time 
            clean_cache()
    except Exception as e:
        print(f"[FAIL] Error: {e}")

def clean_cache():
    current_time = time.time()
    to_delete = [ip for ip, ts in reported_cache.items() if current_time - ts > REPORT_INTERVAL]
    for ip in to_delete:
        del reported_cache[ip]

def monitor_logs():
    print("🚀 Monitoring logs (Alpine SysWarden Reporter)...")
    
    # Files to watch on Alpine
    files_to_watch = []
    if os.path.exists("/var/log/messages"): files_to_watch.append("/var/log/messages")
    if os.path.exists("/var/log/fail2ban.log"): files_to_watch.append("/var/log/fail2ban.log")
    
    if not files_to_watch:
        print("[FAIL] No log files found to monitor.")
        return

    cmd = ['tail', '-F'] + files_to_watch
    f = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p = select.poll()
    p.register(f.stdout)

    regex_fw = re.compile(r"\[SysWarden-BLOCK\].*SRC=([\d\.]+).*DPT=(\d+)")
    regex_f2b = re.compile(r"\[([a-zA-Z0-9_-]+)\]\s+Ban\s+([\d\.]+)")

    while True:
        if p.poll(100):
            line = f.stdout.readline().decode('utf-8', errors='ignore')
            if not line: continue

            # --- FIREWALL LOGIC ---
            if ENABLE_FW:
                match_fw = regex_fw.search(line)
                if match_fw:
                    ip = match_fw.group(1)
                    try:
                        port = int(match_fw.group(2))
                    except ValueError:
                        port = 0
                    
                    cats = ["14"]
                    attack_type = "Port Scan"

                    if port in [80, 443]: cats.extend(["20", "21"]); attack_type = "Web Attack"
                    elif port in [22, 2222]: cats.extend(["18", "22"]); attack_type = "SSH Attack"
                    elif port == 23: cats.extend(["18", "23"]); attack_type = "Telnet IoT"
                    elif port == 445: cats.extend(["15", "18"]); attack_type = "SMB"
                    elif port == 1433: cats.extend(["18", "15"]); attack_type = "MSSQL"
                    elif port in [3389, 5900]: cats.extend(["18"]); attack_type = "RDP/VNC"

                    send_report(ip, ",".join(cats), f"Blocked by SysWarden Firewall ({attack_type} Port {port})")
                    continue

            # --- FAIL2BAN LOGIC ---
            if ENABLE_F2B:
                match_f2b = regex_f2b.search(line)
                if match_f2b and "SysWarden-BLOCK" not in line:
                    jail = match_f2b.group(1)
                    ip = match_f2b.group(2)
                    
                    cats = ["18"] # General Abuse
                    if "ssh" in jail.lower(): cats.extend(["22"])
                    elif "nginx" in jail.lower() or "apache" in jail.lower(): cats.extend(["21"])

                    send_report(ip, ",".join(cats), f"Banned by Fail2ban (Jail: {jail})")

if __name__ == "__main__":
    monitor_logs()
EOF

        # Replace placeholders based on user choices
        local PY_F2B="False"; if [[ "$REPORT_F2B" =~ ^[Yy]$ ]]; then PY_F2B="True"; fi
        local PY_FW="False"; if [[ "$REPORT_FW" =~ ^[Yy]$ ]]; then PY_FW="True"; fi

        sed -i "s/PLACEHOLDER_KEY/$USER_API_KEY/" /usr/local/bin/syswarden_reporter.py
        sed -i "s/PLACEHOLDER_F2B/$PY_F2B/" /usr/local/bin/syswarden_reporter.py
        sed -i "s/PLACEHOLDER_FW/$PY_FW/" /usr/local/bin/syswarden_reporter.py
        
        chmod +x /usr/local/bin/syswarden_reporter.py

        log "INFO" "Creating OpenRC service for Reporter..."
        cat <<'EOF' > /etc/init.d/syswarden-reporter
#!/sbin/openrc-run

name="syswarden-reporter"
description="SysWarden Unified Reporter for AbuseIPDB"
command="/usr/local/bin/syswarden_reporter.py"
command_background=true
pidfile="/run/${name}.pid"

depend() {
    need net
    after firewall
}
EOF
        chmod +x /etc/init.d/syswarden-reporter
        rc-update add syswarden-reporter default >/dev/null 2>&1
        rc-service syswarden-reporter restart >/dev/null 2>&1
        log "INFO" "AbuseIPDB Unified Reporter is ACTIVE."
        
    else
        log "INFO" "Skipping AbuseIPDB reporting setup."
    fi
}

detect_protected_services() {
    echo -e "\n${BLUE}=== Step 5: Service Integration Check ===${NC}"
    if command -v fail2ban-client >/dev/null && rc-service fail2ban status 2>/dev/null | grep -q "started"; then
        JAILS=$(fail2ban-client status | grep "Jail list" | sed 's/.*Jail list://g')
        log "INFO" "Fail2ban is ACTIVE. Jails: ${JAILS}"
    else
        log "WARN" "Fail2ban not active."
    fi
}

setup_siem_logging() {
    echo -e "\n${BLUE}=== Step 6: SIEM Logging Status ===${NC}"
    log "INFO" "Logs are ready in /var/log/messages and /var/log/fail2ban.log"
}

setup_cron_autoupdate() {
    if [[ "${1:-}" != "update" ]]; then
        local script_path=$(realpath "$0")
        
        # Add to root's crontab natively for Alpine
        if ! grep -q "syswarden-update" /etc/crontabs/root 2>/dev/null; then
             echo "5 * * * * $script_path update >/dev/null 2>&1 # syswarden-update" >> /etc/crontabs/root
             rc-update add crond default >/dev/null 2>&1 || true
             rc-service crond restart >/dev/null 2>&1 || true
             log "INFO" "Automatic updates enabled via Crond."
        fi

        cat <<EOF > /etc/logrotate.d/syswarden
/var/log/messages
/var/log/syslog
$LOG_FILE {
    daily
    rotate 7
    compress
    missingok
    notifempty
    postrotate
        /etc/init.d/syslog reload >/dev/null 2>&1 || true
    endscript
}
EOF
    fi
}

uninstall_syswarden() {
    echo -e "\n${RED}=== Uninstalling SysWarden (Alpine) ===${NC}"
    log "WARN" "Starting Deep Clean Uninstallation..."

    if [[ -f "$CONF_FILE" ]]; then source "$CONF_FILE"; fi

    # 1. Stop & Remove Reporter Service
    log "INFO" "Removing SysWarden Reporter..."
    rc-service syswarden-reporter stop 2>/dev/null || true
    rc-update del syswarden-reporter default 2>/dev/null || true
    rm -f /etc/init.d/syswarden-reporter /usr/local/bin/syswarden_reporter.py

    # 2. Remove Cron & Logrotate
    log "INFO" "Removing Maintenance Tasks..."
    sed -i '/syswarden-update/d' /etc/crontabs/root 2>/dev/null || true
    rc-service crond restart 2>/dev/null || true
    rm -f "/etc/logrotate.d/syswarden"

    # 3. Clean Firewall Rules
    log "INFO" "Cleaning Firewall Rules..."
    
    # Nftables
    if command -v nft >/dev/null; then 
        nft delete table inet syswarden_table 2>/dev/null || true
        nft list ruleset > /etc/nftables.nft 2>/dev/null || true
    fi
    
    # IPSet / Iptables (Legacy)
    if command -v ipset >/dev/null; then 
        ipset destroy "$SET_NAME" 2>/dev/null || true
        /etc/init.d/iptables save 2>/dev/null || true
    fi

    # 4. Revert Fail2ban Configuration
    if [[ -f /etc/fail2ban/jail.local.bak ]]; then
        log "INFO" "Restoring original Fail2ban configuration..."
        mv /etc/fail2ban/jail.local.bak /etc/fail2ban/jail.local
        rc-service fail2ban restart 2>/dev/null || true
    elif [[ -f /etc/fail2ban/jail.local ]]; then
        log "INFO" "No backup found. Removing SysWarden jail.local..."
        rm /etc/fail2ban/jail.local
        rc-service fail2ban restart 2>/dev/null || true
    fi

    # 5. Remove Config File & Logs
    rm -f "$CONF_FILE"
    rm -f "$LOG_FILE"
    
    log "INFO" "Cleanup complete. Environment restored."
    echo -e "${GREEN}Uninstallation complete.${NC}"
    exit 0
}

setup_wazuh_agent() {
    echo -e "\n${BLUE}=== Step 8: Wazuh Agent Installation (Alpine) ===${NC}"
    
    read -p "Install Wazuh Agent? (y/N): " response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        log "INFO" "Skipping Wazuh Agent installation."
        return
    fi

    read -p "Enter Wazuh Manager IP: " WAZUH_IP
    if [[ -z "$WAZUH_IP" ]]; then log "ERROR" "Missing IP. Skipping."; return; fi

    read -p "Agent Communication Port [Press Enter for '1514']: " W_PORT_COMM
    W_PORT_COMM=${W_PORT_COMM:-1514}

    read -p "Enrollment Port [Press Enter for '1515']: " W_PORT_ENROLL
    W_PORT_ENROLL=${W_PORT_ENROLL:-1515}

    log "INFO" "Whitelisting Wazuh Manager IP ($WAZUH_IP) on Alpine Firewall..."
    
    if [[ "$FIREWALL_BACKEND" == "nftables" ]]; then
         nft insert rule inet syswarden_table input ip saddr "$WAZUH_IP" accept 2>/dev/null || true
         nft list ruleset > /etc/nftables.nft
         log "INFO" "Nftables rule added for Wazuh Manager."
    else
         if ! iptables -C INPUT -s "$WAZUH_IP" -j ACCEPT 2>/dev/null; then
             iptables -I INPUT 1 -s "$WAZUH_IP" -j ACCEPT
             /etc/init.d/iptables save >/dev/null 2>&1 || true
         fi
    fi

    log "INFO" "Starting Wazuh Agent installation via Apk..."
    
    # Install directly from Wazuh repo for Alpine
    if apk add -q --allow-untrusted https://packages.wazuh.com/4.x/alpine/v3.14/main/x86_64/wazuh-agent-4.9.0-1.alpine.x86_64.apk; then
        
        # Inject Custom Settings into OSSEC Config
        if [[ -f /var/ossec/etc/ossec.conf ]]; then
            sed -i "s/<address>.*<\/address>/<address>$WAZUH_IP<\/address>/" /var/ossec/etc/ossec.conf
            sed -i "s/<port>1514<\/port>/<port>$W_PORT_COMM<\/port>/" /var/ossec/etc/ossec.conf
        fi

        rc-update add wazuh-agent default >/dev/null 2>&1
        rc-service wazuh-agent restart >/dev/null 2>&1
        
        echo "WAZUH_IP='$WAZUH_IP'" >> "$CONF_FILE"
        echo "WAZUH_COMM_PORT='$W_PORT_COMM'" >> "$CONF_FILE"
        log "INFO" "Wazuh Agent installed and started."
    else
        log "ERROR" "Failed to install Wazuh Agent package."
    fi
}

whitelist_ip() {
    echo -e "\n${BLUE}=== SysWarden Whitelist Manager ===${NC}"
    read -p "Enter IP to Whitelist: " WL_IP

    if [[ ! "$WL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "ERROR" "Invalid IP format."
        return
    fi

    log "INFO" "Whitelisting IP: $WL_IP on backend: $FIREWALL_BACKEND"

    case "$FIREWALL_BACKEND" in
        "nftables")
            nft insert rule inet syswarden_table input ip saddr "$WL_IP" accept
            nft list ruleset > /etc/nftables.nft
            log "INFO" "Rule added to Nftables and saved."
            ;;
        *)
            iptables -I INPUT 1 -s "$WL_IP" -j ACCEPT
            /etc/init.d/iptables save >/dev/null 2>&1 || true
            log "INFO" "Rule added to IPTables."
            ;;
    esac
}

blocklist_ip() {
    echo -e "\n${RED}=== SysWarden Manual Blocklist Manager ===${NC}"
    read -p "Enter IP to Block: " BL_IP

    if [[ ! "$BL_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "ERROR" "Invalid IP format."
        return
    fi

    log "INFO" "Blocking IP: $BL_IP on backend: $FIREWALL_BACKEND"

    case "$FIREWALL_BACKEND" in
        "nftables")
            nft insert rule inet syswarden_table input ip saddr "$BL_IP" drop
            nft list ruleset > /etc/nftables.nft
            log "INFO" "Drop rule added to Nftables and saved."
            ;;
        *)
            iptables -I INPUT 1 -s "$BL_IP" -j DROP
            /etc/init.d/iptables save >/dev/null 2>&1 || true
            log "INFO" "Drop rule added to IPTables."
            ;;
    esac
}

show_alerts_dashboard() {
    trap "tput cnorm; clear; exit 0" INT TERM
    tput civis

    while true; do
        clear
        local NOW=$(date "+%H:%M:%S")
        
        echo -e "${BLUE}====================================================================================================${NC}"
        echo -e "${BLUE}   SysWarden Live Attack Dashboard (Last Update: $NOW)        ${NC}"
        echo -e "${BLUE}====================================================================================================${NC}"
        printf "${YELLOW}%-19s | %-10s | %-16s | %-20s | %-12s | %-8s${NC}\n" "DATE / HOUR" "SOURCE" "IP ADDRESS" "RULES" "PORT" "DECISION"
        echo "----------------------------------------------------------------------------------------------------"

        local date_regex="^([A-Z][a-z]{2}[[:space:]]+[0-9]+[[:space:]]+[0-9:]+|[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]]+[0-9:]+)"

        # 1. FAIL2BAN ENTRIES (Via Flat File)
        if [[ -f "/var/log/fail2ban.log" ]]; then
             { grep " Ban " "/var/log/fail2ban.log" || true; } | tail -n 8 | while read -r line; do
                if [[ $line =~ \[([a-zA-Z0-9_-]+)\][[:space:]]+Ban[[:space:]]+([0-9.]+) ]]; then
                    jail="${BASH_REMATCH[1]}"
                    ip="${BASH_REMATCH[2]}"
                    dtime="Unknown"
                    if [[ $line =~ $date_regex ]]; then dtime="${BASH_REMATCH[1]}"; fi
                    printf "%-19s | %-10s | %-16s | %-20s | %-12s | %-8s\n" "$dtime" "Fail2ban" "$ip" "$jail" "Dynamic" "BAN"
                fi
            done
        fi

        # 2. FIREWALL ENTRIES (Via Flat File)
        if [[ -f "/var/log/messages" ]]; then
             { grep "SysWarden-BLOCK" "/var/log/messages" || true; } | tail -n 12 | while read -r line; do
                if [[ $line =~ SRC=([0-9.]+) ]]; then
                    ip="${BASH_REMATCH[1]}"
                    rule="SysWarden-BLOCK"
                    port="Global"
                    if [[ $line =~ DPT=([0-9]+) ]]; then port="TCP/${BASH_REMATCH[1]}"; fi
                    dtime="Unknown"
                    if [[ $line =~ $date_regex ]]; then dtime="${BASH_REMATCH[1]}"; fi
                    
                    printf "%-19s | %-10s | %-16s | %-20s | %-12s | %-8s\n" "$dtime" "Firewall" "$ip" "$rule" "$port" "BLOCK"
                fi
             done
        fi
        
        echo "----------------------------------------------------------------------------------------------------"
        echo -e "Press [ESC] to Quit."
        
        read -t 10 -n 1 -s -r key || true
        if [[ $key == $'\e' ]]; then
            break
        fi
    done
    tput cnorm
    clear
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

MODE="${1:-install}"

if [[ "$MODE" == "whitelist" ]]; then
    check_root
    detect_os_backend
    whitelist_ip
    exit 0
fi

if [[ "$MODE" == "blocklist" ]]; then
    check_root
    detect_os_backend
    blocklist_ip
    exit 0
fi

if [[ "$MODE" == "alerts" ]]; then
    check_root
    show_alerts_dashboard
    exit 0
fi

if [[ "$MODE" == "uninstall" ]]; then
    check_root
    uninstall_syswarden
fi

if [[ "$MODE" != "update" ]]; then
    clear
    echo -e "${GREEN}#############################################################"
    echo -e "#     SysWarden Tool Installer (Alpine Linux Edition)       #"
    echo -e "#############################################################${NC}"
fi

check_root
detect_os_backend

if [[ "$MODE" != "update" ]]; then
    install_dependencies
    define_ssh_port "$MODE"
    configure_fail2ban
fi

select_list_type "$MODE"
select_mirror "$MODE"
download_list
apply_firewall_rules
detect_protected_services

if rc-service syswarden-reporter status 2>/dev/null | grep -q "started"; then
    rc-service syswarden-reporter restart >/dev/null 2>&1 || true
fi

if [[ "$MODE" != "update" ]]; then
    setup_siem_logging
    setup_abuse_reporting
    setup_wazuh_agent
    setup_cron_autoupdate "$MODE"
    
    echo -e "\n${GREEN}INSTALLATION SUCCESSFUL${NC}"
    echo -e " -> OS Detected: Alpine Linux (OpenRC)"
    echo -e " -> List loaded: $LIST_TYPE"
    echo -e " -> Protection: Active"
fi