// Package command implements the keephippo CLI subcommands. In Phase 1 it
// provides version/info, the server (real and -dev), operator init/unseal, and
// status; later phases add secrets/auth/policy/token/kv and friends.
package command

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jfigge/keephippo/internal/version"
)

// Execute runs the root command and returns a process exit code following
// Vault's conventions: 0 success, 2 for usage/argument errors, 1 otherwise
// (a command may request a specific code via an exitCoder error).
func Execute() int {
	reached := false
	root := newRootCmd()
	root.PersistentPreRun = func(*cobra.Command, []string) { reached = true }
	// Accept Vault-style single-dash long flags (-path, -dev, …) in addition to
	// cobra's double-dash form.
	root.SetArgs(normalizeArgs(os.Args[1:]))

	err := root.Execute()
	if err == nil {
		return 0
	}

	var ec exitCoder
	if errors.As(err, &ec) {
		fmt.Fprintln(os.Stderr, err.Error())
		return ec.ExitCode()
	}
	fmt.Fprintln(os.Stderr, "Error:", err)
	if !reached {
		return 2 // usage / flag / argument error (the command body never ran)
	}
	return 1
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
		newPolicyCmd(),
		newTokenCmd(),
		newLoginCmd(),
		newAuthCmd(),
		newAuditCmd(),
		newLeaseCmd(),
		newTransitCmd(),
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
