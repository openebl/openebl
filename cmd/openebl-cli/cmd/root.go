package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "openebl-cli",
	Short: "OpenEBL command-line interface",
	Long: `OpenEBL command-line interface for managing Business Units and certificates.
This CLI tool provides commands for onboarding businesses to the OpenEBL platform.`,
}

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringP("bu-server", "b", "http://localhost:9200", "Business Unit server address")
	rootCmd.PersistentFlags().StringP("ca-server", "c", "http://localhost:9100", "Certificate Authority server address")
	rootCmd.PersistentFlags().StringP("requester", "r", "", "Name of the requester")
	rootCmd.PersistentFlags().String("api-key", "", "API key for authentication with the BU server")
	
	// Add commands
	rootCmd.AddCommand(onboardCmd)
}

func exitWithError(msg string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", msg, err)
	os.Exit(1)
}
