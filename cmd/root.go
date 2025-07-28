package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "fastshare",
	Short: "FastShare is a CLI tool for insanely fast file transfers",
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	// register subcommands
	rootCmd.AddCommand(sendCmd)
	rootCmd.AddCommand(recvCmd)
}
