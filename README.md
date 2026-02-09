<p align="center">
  <img src="https://img.shields.io/badge/Open%20Source-100%25-brightgreen?style=for-the-badge&logo=opensourceinitiative">
  <img src="https://img.shields.io/badge/powered%20by-DuggyTuxy-darkred?style=for-the-badge&logo=apachekafka">
  <img src="https://img.shields.io/badge/Status-Community--Professional-brightgreen?style=for-the-badge&logo=status">
  <img src="https://img.shields.io/badge/Security-Hardened-blue?style=for-the-badge&logo=security">
  <img src="https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu%20%7C%20AlmaLinux%20%7C%20RockyLinux%20%7C%20RHEL-orange?style=for-the-badge&logo=platform">
  <img src="https://img.shields.io/badge/License-GNU_GPLv3-0052cc?style=for-the-badge&logo=license">
  <img src="https://img.shields.io/github/last-commit/duggytuxy/syswarden?label=Last%20Update&color=informational&style=for-the-badge&logo=github">
</p>

<div align="center">
  <a href="https://duggytuxy.github.io/" target="_blank">Website</a>
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="https://github.com/duggytuxy/syswarden/issues">Issues Tracker</a>
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="https://www.linkedin.com/in/laurent-minne/" target="_blank">Linkedin</a>
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="https://tryhackme.com/p/duggytuxy" target="_blank">TryHackMe</a>
  <span>&nbsp;&nbsp;•&nbsp;&nbsp;</span>
  <a href="https://ko-fi.com/laurentmduggytuxy" target="_blank">Ko-Fi</a>
  <br />
</div>

<p align="center">
  <br />
  <a href="https://ko-fi.com/L4L71HRILD" target="_blank">
    <img src="https://ko-fi.com/img/githubbutton_sm.svg" alt="Support me on Ko-fi">
  </a>
  <br />
</p>

![Alt](https://repobeats.axiom.co/api/embed/d909eab3c0cafb3a64294546f37a130f18a7e2f0.svg "Repobeats analytics image")

# SysWarden

SysWarden is a tool based on the **[Data-Shield IPv4 Blocklists Community](https://github.com/duggytuxy/Data-Shield_IPv4_Blocklist)** and **[Fail2ban](https://github.com/fail2ban/fail2ban)** that blocks up to 99% of noisy, disruptive, and malicious IP addresses and focuses on real signals.

## Key Features

- **Universal OS Support:** Auto-detects and adapts to **Debian, Ubuntu, RHEL, AlmaLinux, and Rocky Linux**.

- **Intelligent Backend Detection:** Automatically selects the best firewall technology present on your system:
  - **Firewalld** (RHEL/Alma/Rocky native integration)
  - **Nftables** (Modern Debian/Ubuntu standard)
  - **IPSet/Iptables** (Legacy support)
  
- **Smart Mirror Selection:** Replaced ICMP Pings with **TCP/HTTP latency checks** to bypass firewall restrictions on GitHub/GitLab, ensuring you always download from the fastest mirror.

- **Kernel-Safe Optimization:**
  - Enables high-performance memory hashing (`hashsize`) on Debian/Ubuntu.
  - Uses conservative, stability-first settings on RHEL/Rocky kernels to prevent "Invalid Argument" crashes.
  
- **Persistence Guaranteed:** Rules are written to disk (XML for Firewalld, persistent saves for Netfilter), surviving reboots instantly.

- **Auto-Update:** Installs a cron job to refresh the blocklist hourly.

## Technical Deep Dive: Integration Logic
> Many admins worry that installing a massive blocklist might conflict with Fail2ban. **SysWarden solves this via layering.**

### 1. The Nftables + Fail2ban Synergy (Debian/Ubuntu)

- **Data-Shield (Layer 1):** Creates a high-performance Nftables `set` containing ~100k IPs. This acts as a static shield, dropping known bad actors instantly using extremely efficient kernel-level lookups.
- **Fail2ban (Layer 2):** Continues to monitor logs for *new*, unknown attackers.
- **Result:** Fail2ban uses less CPU because Data-Shield filters out the "background noise" (99% of automated scans) before Fail2ban even has to parse a log line.

### 2. The Firewalld + Fail2ban Synergy (RHEL/Alma/Rocky)

On Enterprise Linux, proper integration with `firewalld` is critical.

- **Native Sets:** SysWarden creates a permanent `ipset` type within Firewalld's configuration logic.
- **Rich Rules:** It applies a "Rich Rule" that drops traffic from this set *before* it reaches your zones or services.
- **Persistence:** Unlike simple scripts that run `ipset` commands (which vanish on reload), SysWarden writes the configuration to `/etc/firewalld/`, ensuring the protection persists across service reloads and server reboots.

### 3. AbuseIPDB reporting
> In a community setting, during the script installation phase, it is possible to report triggered and confirmed alerts to ABUSEIPDB in order to keep the database of malicious IP addresses up to date.

- **Enable the option** Simply confirm with `y` when prompted during installation.
- **API key** Paste your AbuseIPDB API key to automatically report malicious IPs and contribute to the community database.

### Project Objectives

- **Noise Reduction:** Drastically reduce the size of system logs (`/var/log/auth.log`, `journalctl`) by blocking scanners at the door.
- **Resource Saving:** Save CPU cycles and bandwidth by dropping packets at the kernel level rather than letting application servers (Nginx, SSHD) handle them.
- **Proactive Security:** Move from a "Reactive" stance (wait for 5 failed logins -> Ban) to a "Proactive" stance (Ban the IP because it attacked a server in another country 10 minutes ago).

## How to Install (root)

```bash
# For Ubuntu/Debian
apt update && apt upgrade -y
apt install wget -y

# For Rocky/AlmaLinux/RHEL
dnf update -y
dnf install wget -y

# install script
cd /usr/local/bin/
wget https://github.com/duggytuxy/syswarden/releases/download/v1.01/install-syswarden.sh
chmod +x install-syswarden.sh
./install-syswarden.sh

# Check Kernel Logs
journalctl -k -f | grep "SysWarden-BLOCK"
```

## Uninstallation (root)

```bash
./install-syswarden.sh uninstall
```

## Support & Sustainability

> **Help keep the tool alive**
> Developing and maintaining a high-fidelity, real-time blocklist requires significant infrastructure resources and dedicated time. Your contributions are vital to ensure the project remains sustainable, up-to-date, and free for the community.
> If you find this project useful, consider supporting its ongoing development:

* ☕ **Ko-Fi:** [https://ko-fi.com/laurentmduggytuxy](https://ko-fi.com/laurentmduggytuxy)

## License & Copyright

- **SysWarden** © 2023–2026  
- Developed by **Duggy Tuxy (Laurent Minne)**.

"This tool is open-source software licensed under the **[GNU GPLv3 License](/LICENSE)**." 
