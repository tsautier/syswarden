package cmd

import (
	"fmt"

	"syswarden-cli/pkg/firewall"
	"syswarden-cli/pkg/integration"

	"github.com/spf13/cobra"
)

var blockCmd = &cobra.Command{
	Use:   "block <IP>...",
	Short: "Hot-adds an IP to the kernel drop set",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		for _, ip := range args {
			if err := firewall.AddToBlocklist(ip); err != nil {
				fmt.Printf("[ERROR] %s: %v\n", ip, err)
			} else {
				// Send Discord/Teams Notification for Manual Block
				integration.SendBanAlert(ip)
			}
		}
	},
}

func init() { rootCmd.AddCommand(blockCmd) }
