package command

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jfigge/keephippo/api"
)

// addClientFlags registers the persistent connection flags shared by the
// client-facing subcommands.
func addClientFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("address", "", "Address of the keephippo server (env KEEPHIPPO_ADDR / VAULT_ADDR)")
	cmd.PersistentFlags().Bool("tls-skip-verify", false, "Disable TLS certificate verification (insecure)")
	cmd.PersistentFlags().String("format", "table", `Output format: "table" or "json"`)
	cmd.PersistentFlags().String("wrap-ttl", "", "Wrap the response in a single-use token with this TTL (e.g. 60s)")
}

// newClient builds an API client from the connection flags, environment, and
// stored token.
func newClient(cmd *cobra.Command) (*api.Client, error) {
	return newClientWithToken(cmd, resolveToken())
}

func newClientWithToken(cmd *cobra.Command, token string) (*api.Client, error) {
	skip, _ := cmd.Flags().GetBool("tls-skip-verify")
	wrapTTL, _ := cmd.Flags().GetString("wrap-ttl")
	return api.NewClient(api.Config{
		Address:       resolveAddr(cmd),
		Token:         token,
		TLSSkipVerify: skip,
		WrapTTL:       wrapTTL,
	})
}

// resolveAddr resolves the server address: --address, then KEEPHIPPO_ADDR, then
// VAULT_ADDR (the client defaults to http://127.0.0.1:8200 if all are empty).
func resolveAddr(cmd *cobra.Command) string {
	if addr, _ := cmd.Flags().GetString("address"); addr != "" {
		return addr
	}
	return firstEnv("KEEPHIPPO_ADDR", "VAULT_ADDR")
}

// resolveToken resolves the client token: KEEPHIPPO_TOKEN, then VAULT_TOKEN,
// then the token stored by `keephippo login`.
func resolveToken() string {
	if t := firstEnv("KEEPHIPPO_TOKEN", "VAULT_TOKEN"); t != "" {
		return t
	}
	return readStoredToken()
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// --- token helper (like Vault's ~/.vault-token) ---

func tokenHelperPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".keephippo-token"
	}
	return filepath.Join(home, ".keephippo-token")
}

func storeToken(token string) error {
	return os.WriteFile(tokenHelperPath(), []byte(token), 0o600)
}

func readStoredToken() string {
	b, err := os.ReadFile(tokenHelperPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
