package cmd

import (
	"context"
	"fmt"

	"fastshare-cli/internal/quic"

	"github.com/spf13/cobra"
)

var outDir string

var recvCmd = &cobra.Command{
	Use:   "recv [link]",
	Short: "Receive a file using a share link",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		link := args[0]
		fmt.Printf("Receiving file with link: %s, saving to: %s\n", link, outDir)
		return quic.ReceiveFile(context.Background(), link, outDir)
	},
}

func init() {
	recvCmd.Flags().StringVarP(&outDir, "out", "o", ".", "Output directory for received file")
}
