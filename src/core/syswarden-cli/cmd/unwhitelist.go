package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"syswarden-cli/pkg/firewall"
)

var unwhitelistCmd = &cobra.Command{
	Use:   "unwhitelist <IP>",
	Short: "Revokes global VIP access",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := firewall.RemoveFromWhitelist(args[0]); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

func init() { rootCmd.AddCommand(unwhitelistCmd) }
