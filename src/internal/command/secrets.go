package command

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func newSecretsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "Manage secrets engines",
	}
	cmd.AddCommand(newSecretsEnableCmd(), newSecretsDisableCmd(), newSecretsListCmd(), newSecretsMoveCmd())
	return cmd
}

func newSecretsMoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "move SOURCE DEST",
		Short: "Move a secrets engine to a new path",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			from := strings.Trim(args[0], "/")
			to := strings.Trim(args[1], "/")
			if err := c.MountRemount(from, to); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Success! Moved secrets engine %s/ to: %s/\n", from, to)
			return nil
		},
	}
}

func newSecretsEnableCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "enable [-path=PATH] TYPE",
		Short: "Enable a secrets engine",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			typ := args[0]
			p := strings.Trim(path, "/")
			if p == "" {
				p = typ
			}
			if err := c.MountEnable(p, typ); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Success! Enabled the %s secrets engine at: %s/\n", typ, p)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "Path to mount the engine at (default: the type name)")
	return cmd
}

func newSecretsDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable PATH",
		Short: "Disable a secrets engine",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			p := strings.Trim(args[0], "/")
			if err := c.MountDisable(p); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Success! Disabled the secrets engine (if it existed) at: %s/\n", p)
			return nil
		},
	}
}

func newSecretsListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List enabled secrets engines",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			mounts, err := c.ListMounts()
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%-16s%s\n", "Path", "Type")
			fmt.Fprintf(w, "%-16s%s\n", "----", "----")
			for _, p := range sortedKeys(mounts) {
				m, _ := mounts[p].(map[string]any)
				fmt.Fprintf(w, "%-16s%v\n", p, m["type"])
			}
			return nil
		},
	}
}
