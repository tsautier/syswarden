package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"syswarden-cli/pkg/system"
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Completely remove SysWarden from the system",
	Run: func(cmd *cobra.Command, args []string) {
		if err := system.UninstallSystem(); err != nil {
			fmt.Printf("[ERROR] %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(uninstallCmd)
}
