package cmd

import (
	"fmt"
	"os"

	"syswarden-cli/pkg/firewall"
	"syswarden-cli/pkg/integration"
	"github.com/spf13/cobra"
)

var blockCmd = &cobra.Command{
	Use:   "block <IP>",
	Short: "Hot-adds an IP to the kernel drop set",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := firewall.AddToBlocklist(args[0]); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		// Send Discord/Teams Notification for Manual Block
		integration.SendBanAlert(args[0])
		fmt.Printf("[SUCCESS] IP %s safely blocklisted.\n", args[0])
	},
}

func init() { rootCmd.AddCommand(blockCmd) }
