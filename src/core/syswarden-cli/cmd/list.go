package cmd

import (
	"syswarden-cli/pkg/firewall"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "Displays all custom IP registries",
	Run: func(cmd *cobra.Command, args []string) {
		firewall.ListIPs()
	},
}

func init() { rootCmd.AddCommand(listCmd) }
