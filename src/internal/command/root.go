// Package command implements the keephippo CLI subcommands. In Phase 1 it
// provides version/info, the server (real and -dev), operator init/unseal, and
// status; later phases add secrets/auth/policy/token/kv and friends.
package command

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jfigge/keephippo/internal/version"
)

// Execute runs the root command and returns a process exit code.
func Execute() int {
	root := newRootCmd()
	// Accept Vault-style single-dash long flags (-path, -dev, …) in addition to
	// cobra's double-dash form.
	root.SetArgs(normalizeArgs(os.Args[1:]))
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	return 0
}

var singleDashLongFlag = regexp.MustCompile(`^-[a-zA-Z][a-zA-Z0-9-]+`)

// normalizeArgs rewrites single-dash long flags (e.g. -path=x, -dev) to their
// double-dash form. Single-character flags (-h, -v) are left untouched.
func normalizeArgs(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && singleDashLongFlag.MatchString(a) {
			out[i] = "-" + a
		} else {
			out[i] = a
		}
	}
	return out
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
	addClientFlags(root)
	root.AddCommand(
		newVersionCmd(),
		newInfoCmd(),
		newServerCmd(),
		newOperatorCmd(),
		newStatusCmd(),
		newSecretsCmd(),
		newKVCmd(),
		newReadCmd(),
		newWriteCmd(),
		newDeleteCmd(),
		newListCmd(),
	)
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
