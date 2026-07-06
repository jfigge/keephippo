package command

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/jfigge/keephippo/api"
)

// addClientFlags registers the persistent connection flags shared by the
// client-facing subcommands.
func addClientFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("address", "", "Address of the keephippo server (env KEEPHIPPO_ADDR / VAULT_ADDR)")
	cmd.PersistentFlags().Bool("tls-skip-verify", false, "Disable TLS certificate verification (insecure)")
}

// newClient builds an API client from the connection flags and environment.
// Precedence for the address: --address, then KEEPHIPPO_ADDR, then VAULT_ADDR,
// then the default http://127.0.0.1:8200.
func newClient(cmd *cobra.Command) (*api.Client, error) {
	addr, _ := cmd.Flags().GetString("address")
	if addr == "" {
		addr = firstEnv("KEEPHIPPO_ADDR", "VAULT_ADDR")
	}
	skip, _ := cmd.Flags().GetBool("tls-skip-verify")
	return api.NewClient(api.Config{
		Address:       addr,
		Token:         firstEnv("KEEPHIPPO_TOKEN", "VAULT_TOKEN"),
		TLSSkipVerify: skip,
	})
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
