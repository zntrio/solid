package version

import (
	"fmt"

	"github.com/spf13/cobra"
)

// -----------------------------------------------------------------------------

var displayAsJSON bool

// Command exports Cobra command builder
func Command() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Display service version",
		Run: func(cmd *cobra.Command, args []string) {
			if displayAsJSON {
				fmt.Printf("%s", JSON())
			} else {
				fmt.Printf("%s", Full())
			}
		},
	}

	// Register parameters
	cmd.Flags().BoolVar(&displayAsJSON, "json", false, "Display build info as json")

	// Return command
	return cmd
}
