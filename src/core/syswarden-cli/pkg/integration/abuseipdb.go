package integration

import (
	"fmt"
	"os"
	"regexp"
	"syswarden-cli/config"
)

// SetupAbuseIPDB validates and configures AbuseIPDB integration natively
func SetupAbuseIPDB() error {
	if config.GlobalConfig.EnterpriseMode {
		fmt.Println("[WARN] Enterprise Mode is ACTIVE. Third-party telemetry (AbuseIPDB) is strictly disabled.")
		return nil
	}

	if !config.GlobalConfig.EnableAbuse {
		fmt.Println("[INFO] AbuseIPDB reporting is DISABLED by configuration.")
		return nil
	}

	apiKey := config.GlobalConfig.AbuseAPIKey
	if apiKey == "" {
		fmt.Println("[WARN] AbuseIPDB enabled but no API Key provided. Skipping.")
		return nil
	}

	// Validate 80-char API key
	matched, _ := regexp.MatchString("^[a-z0-9]{80}$", apiKey)
	if !matched {
		return fmt.Errorf("invalid AbuseIPDB API key format")
	}

	// Securely save credentials for syswarden-core
	if err := os.MkdirAll("/etc/syswarden", 0750); err != nil {
		return fmt.Errorf("failed to create secrets directory: %v", err)
	}
	secretContent := fmt.Sprintf("SYSWARDEN_ENABLE_ABUSE=y\nSYSWARDEN_ABUSE_API_KEY=%s\n", apiKey)
	if err := os.WriteFile("/etc/syswarden/secrets.env", []byte(secretContent), 0600); err != nil {
		return fmt.Errorf("failed to write secrets file: %v", err)
	}

	fmt.Println("[INFO] AbuseIPDB configuration validated and securely stored.")
	// Note: The actual background reporting logic is handled natively inside syswarden-core (WAF)
	
	fmt.Println("[+] AbuseIPDB Unified Reporter enabled natively via Go WAF.")
	return nil
}
