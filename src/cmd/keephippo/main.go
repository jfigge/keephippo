// Command keephippo is the console application and server for a
// Vault-compatible secrets manager.
//
// Phase 0 wires only `version` and `info`. Later phases add `server`,
// `operator`, and the secrets/auth/policy/token/status commands.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jfigge/keephippo/internal/version"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "keephippo",
		Short:         "keephippo — a Vault-compatible secrets manager",
		Long:          "keephippo is a from-scratch, Vault-compatible secrets manager (server + CLI).",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Short(),
	}
	root.AddCommand(newVersionCmd(), newInfoCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version string",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), version.Short())
			return err
		},
	}
}

func newInfoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "Print version, branch, commit, and build time",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), version.Info())
			return err
		},
	}
}
