package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"syswarden-cli/pkg/firewall"
)

var unblockCmd = &cobra.Command{
	Use:   "unblock <IP>",
	Short: "Purges an IP from the blocklist",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := firewall.RemoveFromBlocklist(args[0]); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

func init() { rootCmd.AddCommand(unblockCmd) }
