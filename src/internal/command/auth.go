package command

import (
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage auth methods",
	}
	cmd.AddCommand(newAuthEnableCmd(), newAuthDisableCmd(), newAuthListCmd())
	return cmd
}

func newAuthEnableCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "enable [-path=PATH] TYPE",
		Short: "Enable an auth method",
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
			if err := c.AuthEnable(p, typ); err != nil {
				return err
			}
			success(cmd, "Success! Enabled %s auth method at: %s/\n", typ, p)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "Path to mount the auth method at (default: the type name)")
	return cmd
}

func newAuthDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable PATH",
		Short: "Disable an auth method",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			p := strings.Trim(args[0], "/")
			if err := c.AuthDisable(p); err != nil {
				return err
			}
			success(cmd, "Success! Disabled the auth method (if it existed) at: %s/\n", p)
			return nil
		},
	}
}

func newAuthListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List enabled auth methods",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			resp, err := c.Do(http.MethodGet, "/v1/sys/auth", nil)
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) { pathTypeTable(w, "Path", resp.Data) })
		},
	}
}
