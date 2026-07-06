package command

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jfigge/keephippo/api"
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
			st, err := c.SealStatus()
			if err != nil {
				return err
			}
			printSealStatus(cmd, st)
			// Match Vault's convention: exit 2 when sealed.
			if st.Sealed {
				os.Exit(2)
			}
			return nil
		},
	}
}

// printSealStatus renders a seal-status response as an aligned key/value table.
func printSealStatus(cmd *cobra.Command, st *api.SealStatusResponse) {
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "%-16s%s\n", "Key", "Value")
	fmt.Fprintf(w, "%-16s%s\n", "---", "-----")
	fmt.Fprintf(w, "%-16s%s\n", "Seal Type", st.Type)
	fmt.Fprintf(w, "%-16s%t\n", "Initialized", st.Initialized)
	fmt.Fprintf(w, "%-16s%t\n", "Sealed", st.Sealed)
	fmt.Fprintf(w, "%-16s%d\n", "Total Shares", st.N)
	fmt.Fprintf(w, "%-16s%d\n", "Threshold", st.T)
	if st.Sealed && st.Initialized {
		fmt.Fprintf(w, "%-16s%d/%d\n", "Unseal Progress", st.Progress, st.T)
	}
	fmt.Fprintf(w, "%-16s%s\n", "Version", st.Version)
	fmt.Fprintf(w, "%-16s%s\n", "Storage Type", st.StorageType)
}
