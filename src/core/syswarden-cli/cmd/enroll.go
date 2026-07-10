package cmd

import (
	"fmt"
	"os"

	"syswarden-cli/pkg/nexus"

	"github.com/spf13/cobra"
)

var (
	enrollURL   string
	enrollToken string
)

var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enroll this node into a SysWarden Nexus fleet",
	Long:  `Securely enroll this server into a centralized SysWarden Nexus management console using a bootstrap token.`,
	Run: func(cmd *cobra.Command, args []string) {
		if enrollURL == "" || enrollToken == "" {
			fmt.Fprintf(os.Stderr, "[ERROR] Both --url and --token are required.\n")
			cmd.Usage()
			os.Exit(1)
		}

		fmt.Println("[*] Initiating Zero-Trust mTLS enrollment with SysWarden Nexus...")
		err := nexus.EnrollNode(enrollURL, enrollToken)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Enrollment failed: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("[SUCCESS] Node successfully enrolled and certificates provisioned.")
		fmt.Println("[*] The 'Sleepy Agent' module will now wake up and synchronize telemetry.")
	},
}

func init() {
	enrollCmd.Flags().StringVar(&enrollURL, "url", "", "The SysWarden Nexus API URL (e.g. https://127.0.0.1:8443)")
	enrollCmd.Flags().StringVar(&enrollToken, "token", "", "The Nexus enrollment token")
	enrollCmd.MarkFlagRequired("url")
	enrollCmd.MarkFlagRequired("token")
	rootCmd.AddCommand(enrollCmd)
}
