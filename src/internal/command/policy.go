package command

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

func newPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Manage ACL policies",
	}
	cmd.AddCommand(newPolicyWriteCmd(), newPolicyReadCmd(), newPolicyListCmd(), newPolicyDeleteCmd())
	return cmd
}

func newPolicyWriteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "write NAME [FILE|-]",
		Short: "Write an ACL policy from a file, or from stdin with '-'",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			var src []byte
			if len(args) == 2 && args[1] != "-" {
				if src, err = os.ReadFile(args[1]); err != nil {
					return err
				}
			} else if src, err = io.ReadAll(cmd.InOrStdin()); err != nil {
				return err
			}
			if err := c.PolicyWrite(args[0], string(src)); err != nil {
				return err
			}
			success(cmd, "Success! Uploaded policy: %s\n", args[0])
			return nil
		},
	}
}

func newPolicyReadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "read NAME",
		Short: "Read an ACL policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			resp, err := c.Do(http.MethodGet, "/v1/sys/policies/acl/"+args[0], nil)
			if err != nil {
				if resp != nil && resp.StatusCode == http.StatusNotFound {
					return &exitError{code: 2, msg: fmt.Sprintf("No policy named: %s", args[0])}
				}
				return err
			}
			return emit(cmd, resp, func(w io.Writer) {
				rules, _ := resp.Data["policy"].(string)
				fmt.Fprintln(w, rules)
			})
		},
	}
}

func newPolicyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List ACL policies",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			resp, err := c.Do("LIST", "/v1/sys/policies/acl", nil)
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) {
				for _, n := range anyToStrings(resp.Data["keys"]) {
					fmt.Fprintln(w, n)
				}
			})
		},
	}
}

func newPolicyDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete NAME",
		Short: "Delete an ACL policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			if err := c.PolicyDelete(args[0]); err != nil {
				return err
			}
			success(cmd, "Success! Deleted policy: %s\n", args[0])
			return nil
		},
	}
}
