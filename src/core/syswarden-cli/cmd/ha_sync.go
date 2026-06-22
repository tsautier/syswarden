package cmd

import (
	"fmt"
	"os"
	"syswarden-cli/pkg/network"

	"github.com/spf13/cobra"
)

var haSyncCmd = &cobra.Command{
	Use:   "ha-sync",
	Short: "Synchronizes the firewall blocklist with the configured HA peer",
	Long:  `Forces an immediate synchronization of the local blocklist to the High Availability standby node over encrypted channels.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := network.SyncHAPeer(); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] HA Sync failed: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(haSyncCmd)
}
