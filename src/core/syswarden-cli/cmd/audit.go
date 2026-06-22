package cmd

import (
	"github.com/spf13/cobra"
	"syswarden-cli/pkg/system"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Performs a full Enterprise SysWarden Audit",
	Run: func(cmd *cobra.Command, args []string) {
		system.RunAudit()
	},
}

func init() { rootCmd.AddCommand(auditCmd) }
