package network

import (
	"bufio"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"syswarden-core/logger"
)

// SaasMonitorDownloader runs in the background and periodically downloads SaaS monitor IPs
type SaasMonitorDownloader struct {
	logger *logger.Logger
}

func NewSaasMonitorDownloader(l *logger.Logger) *SaasMonitorDownloader {
	return &SaasMonitorDownloader{logger: l}
}

func (s *SaasMonitorDownloader) Start() {
	if !s.isSaasAllowed() {
		s.logger.Info("SaaS Monitors Auto-Whitelist is disabled. Skipping downloader.")
		return
	}

	s.logger.Info("Starting SaaS Monitors Downloader (BetterStack) in background...")

	// Initial fetch
	s.fetchMonitors()

	// Periodic fetch every 1 hour
	ticker := time.NewTicker(1 * time.Hour)
	go func() {
		for range ticker.C {
			s.fetchMonitors()
		}
	}()
}

func (s *SaasMonitorDownloader) isSaasAllowed() bool {
	file, err := os.Open("/opt/syswarden/syswarden-auto.conf")
	if err != nil {
		return true // Default to true for safety
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "SYSWARDEN_ALLOW_SAAS_MONITORS=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				val := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
				if strings.ToLower(val) == "n" {
					return false
				}
			}
		}
	}
	return true
}

func (s *SaasMonitorDownloader) fetchMonitors() {
	urls := []string{
		"https://uptime.betterstack.com/ips.txt",
		// Additional SaaS monitor IP lists can be added here
	}

	var allIps []string

	for _, u := range urls {
		ips, err := s.downloadList(u)
		if err != nil {
			s.logger.Error("Failed to fetch SaaS IPs from: "+u, err)
			continue
		}
		allIps = append(allIps, ips...)
	}

	if len(allIps) == 0 {
		return
	}

	// Write to file
	targetFile := "/etc/syswarden/lists/syswarden_saas_monitors.ipv4"
	err := os.WriteFile(targetFile, []byte(strings.Join(allIps, "\n")), 0644)
	if err != nil {
		s.logger.Error("Failed to write SaaS monitors IP list", err)
	}
}

func (s *SaasMonitorDownloader) downloadList(url string) ([]string, error) {
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var ips []string
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			ips = append(ips, line)
		}
	}
	return ips, nil
}
