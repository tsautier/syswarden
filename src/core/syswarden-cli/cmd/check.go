package cmd

import (
	"github.com/spf13/cobra"
	"syswarden-cli/pkg/firewall"
)

var checkCmd = &cobra.Command{
	Use:   "check <IP>",
	Short: "Perform a global diagnostic on an IP",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		firewall.CheckIP(args[0])
	},
}

func init() { rootCmd.AddCommand(checkCmd) }
