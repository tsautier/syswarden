package network

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syswarden-cli/config"
	"time"
)

func getLocalBlocklist() ([]string, error) {
	content, err := os.ReadFile("/etc/syswarden/lists/syswarden_blacklist.ipv4")
	if err != nil {
		return []string{}, nil
	}
	
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	var ips []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			ips = append(ips, l)
		}
	}
	return ips, nil
}

func SyncHAPeer() error {
	if !config.GlobalConfig.HAEnabled {
		fmt.Println("[INFO] HA Sync is disabled in configuration.")
		return nil
	}

	peerIP := config.GlobalConfig.HAPeerIP
	peerPort := config.GlobalConfig.HAPeerPort
	if peerIP == "" {
		return fmt.Errorf("HA Cluster enabled but no Peer IP configured")
	}

	fmt.Printf("[INFO] Starting HA Sync to Peer %s:%s...\n", peerIP, peerPort)

	// Build SSH options based on strict host key checking and cipher
	sshOpts := []string{"-p", peerPort, "-o", "ConnectTimeout=10"}
	if config.GlobalConfig.HAStrictHostKey {
		sshOpts = append(sshOpts, "-o", "StrictHostKeyChecking=yes", "-c", "aes256-gcm@openssh.com")
	} else {
		sshOpts = append(sshOpts, "-o", "StrictHostKeyChecking=accept-new", "-c", "aes256-gcm@openssh.com")
	}

	// 1. Get remote blocklist
	remoteCmdArgs := append(sshOpts, "root@"+peerIP, "cat", "/etc/syswarden/lists/syswarden_blacklist.ipv4")
	remoteOut, err := exec.Command("ssh", remoteCmdArgs...).Output()
	
	remoteIPs := make(map[string]bool)
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(remoteOut)), "\n")
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l != "" {
				remoteIPs[l] = true
			}
		}
	}

	// 2. Get local blocklist
	localIPs, err := getLocalBlocklist()
	if err != nil {
		return err
	}

	// 3. Find IPs to push
	var toPush []string
	for _, ip := range localIPs {
		if !remoteIPs[ip] {
			toPush = append(toPush, ip)
		}
	}

	if len(toPush) == 0 {
		fmt.Println("[+] Peer is already synchronized. No new IPs to push.")
		return nil
	}

	fmt.Printf("[INFO] Found %d new IPs to push to peer. Synchronizing...\n", len(toPush))

	// 4. Push in batches to avoid command line limits
	batchSize := 100
	for i := 0; i < len(toPush); i += batchSize {
		end := i + batchSize
		if end > len(toPush) {
			end = len(toPush)
		}
		
		batch := toPush[i:end]
		
		// Create a script to run on remote to append and apply dynamically without full reload
		remoteScript := fmt.Sprintf(`
for ip in %s; do
  if ! grep -q "^$ip$" /etc/syswarden/lists/syswarden_blacklist.ipv4; then
    echo "$ip" >> /etc/syswarden/lists/syswarden_blacklist.ipv4
  fi
done
nft add element inet syswarden syswarden_blacklist { %s } 2>/dev/null || true
`, strings.Join(batch, " "), strings.Join(batch, ", "))
		
		pushArgs := append(sshOpts, "root@"+peerIP, "bash", "-c", "'"+remoteScript+"'")
		if err := exec.Command("ssh", pushArgs...).Run(); err != nil {
			fmt.Printf("[WARN] Failed to push batch starting at index %d: %v\n", i, err)
		} else {
			time.Sleep(100 * time.Millisecond) // small delay to prevent overwhelming SSH
		}
	}

	fmt.Printf("[+] Successfully synchronized %d IPs to Peer %s.\n", len(toPush), peerIP)
	return nil
}
