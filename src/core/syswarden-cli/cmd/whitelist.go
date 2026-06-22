package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"syswarden-cli/pkg/firewall"
)

var whitelistCmd = &cobra.Command{
	Use:   "whitelist <IP> [PORT]",
	Short: "Grants global VIP access and bypasses the firewall",
	Args:  cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		port := ""
		if len(args) == 2 {
			port = args[1]
		}
		if err := firewall.AddToWhitelist(args[0], port); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

func init() { rootCmd.AddCommand(whitelistCmd) }
