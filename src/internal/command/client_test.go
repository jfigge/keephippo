package command

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestResolveAddrPrecedence(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("address", "", "")

	t.Setenv("VAULT_ADDR", "http://vault:8200")
	t.Setenv("KEEPHIPPO_ADDR", "http://keep:8200")

	// KEEPHIPPO_ADDR wins over VAULT_ADDR.
	if got := resolveAddr(cmd); got != "http://keep:8200" {
		t.Fatalf("resolveAddr = %q; want KEEPHIPPO_ADDR to win", got)
	}
	// --address wins over both.
	if err := cmd.Flags().Set("address", "http://flag:8200"); err != nil {
		t.Fatal(err)
	}
	if got := resolveAddr(cmd); got != "http://flag:8200" {
		t.Fatalf("resolveAddr = %q; want the flag to win", got)
	}
}

func TestResolveTokenPrecedence(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "vtok")
	t.Setenv("KEEPHIPPO_TOKEN", "ktok")
	if got := resolveToken(); got != "ktok" {
		t.Fatalf("resolveToken = %q; want KEEPHIPPO_TOKEN to win", got)
	}
}
