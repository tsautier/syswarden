package cmd

import (
	"github.com/spf13/cobra"
	"syswarden-cli/pkg/firewall"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Displays all custom IP registries",
	Run: func(cmd *cobra.Command, args []string) {
		firewall.ListIPs()
	},
}

func init() { rootCmd.AddCommand(listCmd) }
