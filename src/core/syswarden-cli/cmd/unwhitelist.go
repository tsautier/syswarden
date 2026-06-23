package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"syswarden-cli/pkg/firewall"
)

var unwhitelistCmd = &cobra.Command{
	Use:   "unwhitelist <IP>...",
	Short: "Revokes global VIP access",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		for _, ip := range args {
			if err := firewall.RemoveFromWhitelist(ip); err != nil {
				fmt.Printf("[ERROR] %s: %v\n", ip, err)
			}
		}
	},
}

func init() { rootCmd.AddCommand(unwhitelistCmd) }
