package cmd

import (
	"context"
	"fmt"
	"os"

	"fastshare-cli/internal/quic"

	"github.com/spf13/cobra"
)

var outDir string

var recvCmd = &cobra.Command{
	Use:   "recv",
	Short: "Receive a file from the default sender",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Make sure the output directory exists
		if err := os.MkdirAll(outDir, 0755); err != nil {
			return fmt.Errorf("could not create output dir: %w", err)
		}
		fmt.Printf("Receiving file and saving to: %s\n", outDir)
		return quic.ReceiveFile(context.Background(), outDir)
	},
}

func init() {
	recvCmd.Flags().
		StringVarP(&outDir, "out", "o", ".", "Output directory for received file")
}
