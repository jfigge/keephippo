package command

import (
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/jfigge/keephippo/api"
)

func newTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Create, look up, renew, and revoke tokens",
	}
	cmd.AddCommand(newTokenCreateCmd(), newTokenLookupCmd(), newTokenRenewCmd(), newTokenRevokeCmd(), newTokenCapabilitiesCmd())
	return cmd
}

func newTokenCreateCmd() *cobra.Command {
	var (
		policies    []string
		ttl         string
		numUses     int
		displayName string
		noDefault   bool
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			body := map[string]any{}
			if len(policies) > 0 {
				body["policies"] = policies
			}
			if ttl != "" {
				body["ttl"] = ttl
			}
			if numUses > 0 {
				body["num_uses"] = numUses
			}
			if displayName != "" {
				body["display_name"] = displayName
			}
			if noDefault {
				body["no_default_policy"] = true
			}
			resp, err := c.Do(http.MethodPost, "/v1/auth/token/create", body)
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) { authTable(w, resp) })
		},
	}
	cmd.Flags().StringSliceVar(&policies, "policy", nil, "Policy to attach (repeatable)")
	cmd.Flags().StringVar(&ttl, "ttl", "", "Token TTL (e.g. 1h, 30m)")
	cmd.Flags().IntVar(&numUses, "num-uses", 0, "Max number of uses (0 = unlimited)")
	cmd.Flags().StringVar(&displayName, "display-name", "", "Display name for the token")
	cmd.Flags().BoolVar(&noDefault, "no-default-policy", false, "Do not attach the default policy")
	return cmd
}

func newTokenLookupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lookup [TOKEN]",
		Short: "Look up a token (or the current token if omitted)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			var resp *api.Response
			if len(args) == 1 {
				resp, err = c.Do(http.MethodPost, "/v1/auth/token/lookup", map[string]string{"token": args[0]})
			} else {
				resp, err = c.Do(http.MethodGet, "/v1/auth/token/lookup-self", nil)
			}
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) { kvTable(w, resp.Data) })
		},
	}
}

func newTokenRenewCmd() *cobra.Command {
	var increment string
	cmd := &cobra.Command{
		Use:   "renew TOKEN",
		Short: "Renew a token's lease",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			body := map[string]any{"token": args[0]}
			if increment != "" {
				body["increment"] = increment
			}
			resp, err := c.Do(http.MethodPost, "/v1/auth/token/renew", body)
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) {
				dur := int64(0)
				if resp.Auth != nil {
					dur = resp.Auth.LeaseDuration
				}
				fmt.Fprintf(w, "Success! Renewed token; duration=%d\n", dur)
			})
		},
	}
	cmd.Flags().StringVar(&increment, "increment", "", "Requested renewal increment (e.g. 1h)")
	return cmd
}

func newTokenRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke TOKEN",
		Short: "Revoke a token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			if err := c.TokenRevoke(args[0]); err != nil {
				return err
			}
			success(cmd, "Success! Revoked token (if it existed).\n")
			return nil
		},
	}
}

func newTokenCapabilitiesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "capabilities PATH",
		Short: "Print the current token's capabilities on a path",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			resp, err := c.Do(http.MethodPost, "/v1/sys/capabilities-self", map[string]any{"paths": []string{args[0]}})
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) {
				fmt.Fprintf(w, "%v\n", anyToStrings(resp.Data["capabilities"]))
			})
		},
	}
}
