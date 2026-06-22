package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"syswarden-cli/pkg/system"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Check and install SysWarden updates",
	Run: func(cmd *cobra.Command, args []string) {
		if err := system.UpgradeSystem(); err != nil {
			fmt.Printf("[ERROR] %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
