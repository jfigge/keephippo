package command

import (
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Print the seal status of a keephippo server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			resp, err := c.Do(http.MethodGet, "/v1/sys/seal-status", nil)
			if err != nil {
				return err
			}
			if err := printSealStatus(cmd, resp); err != nil {
				return err
			}
			// Match Vault's convention: exit 2 when sealed.
			if respSealed(resp) {
				os.Exit(2)
			}
			return nil
		},
	}
}
