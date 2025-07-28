package cmd

import (
	"context"
	"fmt"

	"fastshare-cli/internal/quic"

	"github.com/spf13/cobra"
)

var sendCmd = &cobra.Command{
	Use:   "send [file]",
	Short: "Send a file to a peer",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		fmt.Println("Sending file:", filePath)
		// empty addr means listen and print share link
		return quic.SendFile(context.Background(), filePath, "")
	},
}
