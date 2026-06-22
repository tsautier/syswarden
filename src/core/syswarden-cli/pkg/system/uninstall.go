package system

import (
	"fmt"
	"os"
	"os/exec"
)

// UninstallSystem executes a scorched-earth removal of SysWarden and all its dependencies
func UninstallSystem() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("uninstall must be executed as root")
	}

	fmt.Println("[WARN] Starting Deep Clean Uninstallation (Scorched Earth)...")

	// 1. Terminate Daemons
	fmt.Println(" -> Stopping and removing SysWarden Core Services...")
	exec.Command("systemctl", "stop", "syswarden-core.service").Run()
	exec.Command("systemctl", "disable", "syswarden-core.service").Run()
	os.Remove("/etc/systemd/system/syswarden-core.service")

	exec.Command("systemctl", "stop", "syswarden-firewall.service").Run()
	exec.Command("systemctl", "disable", "syswarden-firewall.service").Run()
	os.Remove("/etc/systemd/system/syswarden-firewall.service")

	// Legacy cleanups
	exec.Command("systemctl", "stop", "syswarden.service").Run()
	exec.Command("systemctl", "disable", "syswarden.service").Run()
	os.Remove("/etc/systemd/system/syswarden.service")
	
	exec.Command("systemctl", "stop", "syswarden-reporter").Run()
	exec.Command("systemctl", "disable", "syswarden-reporter").Run()
	os.Remove("/etc/systemd/system/syswarden-reporter.service")

	exec.Command("systemctl", "daemon-reload").Run()

	// 2. Kill orphan processes
	exec.Command("pkill", "-9", "-f", "syswarden-core").Run()

	// 3. Remove WireGuard
	if _, err := os.Stat("/etc/wireguard/wg0.conf"); err == nil {
		fmt.Println(" -> Removing WireGuard VPN configs...")
		exec.Command("systemctl", "disable", "--now", "wg-quick@wg0").Run()
		os.Remove("/etc/wireguard/wg0.conf")
		os.RemoveAll("/etc/wireguard/clients")
		os.Remove("/etc/sysctl.d/99-syswarden-wireguard.conf")
		exec.Command("sysctl", "--system").Run()
	}

	// 4. Clean Firewall Rules
	fmt.Println(" -> Cleaning Firewall Rules (nftables & iptables)...")
	if err := exec.Command("nft", "list", "ruleset").Run(); err == nil {
		exec.Command("nft", "delete", "table", "netdev", "syswarden_hw_drop").Run()
		exec.Command("nft", "delete", "table", "inet", "syswarden").Run()
		exec.Command("nft", "delete", "table", "inet", "syswarden_wg").Run()
	}
	os.Remove("/etc/syswarden/syswarden.nft")
	
	// Legacy iptables purge (DOCKER-USER etc)
	exec.Command("sh", "-c", "iptables-save | grep -v SysWarden | iptables-restore").Run()

	// 5. Revert Hardening
	fmt.Println(" -> Reverting CIS Hardening...")
	os.Remove("/etc/modprobe.d/syswarden-cis-fs.conf")
	os.Remove("/etc/modprobe.d/syswarden-cis-net.conf")
	os.Remove("/etc/sysctl.d/99-syswarden-cis-level2.conf")
	os.Remove("/etc/security/limits.d/99-syswarden-cis.conf")
	exec.Command("sysctl", "--system").Run()

	// 5.5 Clean up Cron and Rsyslog
	fmt.Println(" -> Cleaning up background jobs and log bridges...")
	_ = exec.Command("sh", "-c", "crontab -l | grep -v 'syswarden-cli' | crontab -").Run()
	os.Remove("/etc/rsyslog.d/99-syswarden-waf-bridge.conf")
	os.Remove("/etc/rsyslog.d/99-syswarden-siem.conf")
	exec.Command("systemctl", "restart", "rsyslog").Run()

	// 6. Scorched Earth Files
	fmt.Println(" -> Purging remaining files and configurations...")
	os.RemoveAll("/etc/syswarden")
	os.RemoveAll("/var/lib/syswarden")
	os.RemoveAll("/var/log/syswarden")
	os.Remove("/var/run/syswarden.sock")
	os.Remove("/etc/syswarden.conf")
	os.RemoveAll("/opt/syswarden")
	os.Remove("/usr/local/bin/syswarden")
	os.Remove("/usr/local/bin/syswarden-tui")

	fmt.Println("[SUCCESS] Uninstallation complete. A reboot is recommended.")
	return nil
}
