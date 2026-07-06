package command

import (
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

func newSecretsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secrets",
		Short: "Manage secrets engines",
	}
	cmd.AddCommand(newSecretsEnableCmd(), newSecretsDisableCmd(), newSecretsListCmd(), newSecretsMoveCmd(), newSecretsTuneCmd())
	return cmd
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
			success(cmd, "Success! Enabled the %s secrets engine at: %s/\n", typ, p)
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
			success(cmd, "Success! Disabled the secrets engine (if it existed) at: %s/\n", p)
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
			resp, err := c.Do(http.MethodGet, "/v1/sys/mounts", nil)
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) { pathTypeTable(w, "Path", resp.Data) })
		},
	}
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
			success(cmd, "Success! Moved secrets engine %s/ to: %s/\n", from, to)
			return nil
		},
	}
}
