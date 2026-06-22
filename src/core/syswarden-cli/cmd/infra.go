package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"syswarden-cli/pkg/firewall"
)

var infraCmd = &cobra.Command{
	Use:   "whitelist-infra",
	Short: "Auto-detects and whitelists infrastructure IPs",
	Run: func(cmd *cobra.Command, args []string) {
		if err := firewall.WhitelistInfra(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

func init() { rootCmd.AddCommand(infraCmd) }
