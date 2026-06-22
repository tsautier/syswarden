package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"syswarden-cli/pkg/firewall"
)

var revokeSSHCmd = &cobra.Command{
	Use:   "revoke-ssh <IP>",
	Short: "Revokes direct SSH bypass",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := firewall.RevokeSSH(args[0]); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

func init() { rootCmd.AddCommand(revokeSSHCmd) }
