package command

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Manage audit devices (devices arrive in Phase 7)",
	}
	cmd.AddCommand(newAuditEnableCmd(), newAuditDisableCmd(), newAuditListCmd())
	return cmd
}

func newAuditEnableCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "enable [-path=PATH] TYPE",
		Short: "Enable an audit device",
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
			if _, err := c.Do(http.MethodPost, "/v1/sys/audit/"+p, map[string]string{"type": typ}); err != nil {
				return err
			}
			success(cmd, "Success! Enabled the %s audit device at: %s/\n", typ, p)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "Path for the audit device (default: the type name)")
	return cmd
}

func newAuditDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable PATH",
		Short: "Disable an audit device",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			if _, err := c.Do(http.MethodDelete, "/v1/sys/audit/"+strings.Trim(args[0], "/"), nil); err != nil {
				return err
			}
			success(cmd, "Success! Disabled the audit device (if it existed).\n")
			return nil
		},
	}
}

func newAuditListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List enabled audit devices",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			resp, err := c.Do(http.MethodGet, "/v1/sys/audit", nil)
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) {
				if len(resp.Data) == 0 {
					fmt.Fprintln(w, "No audit devices are enabled.")
					return
				}
				pathTypeTable(w, "Path", resp.Data)
			})
		},
	}
}
