package command

import (
	"fmt"

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
			auth, err := c.TokenCreate(api.TokenCreateRequest{
				Policies:    policies,
				TTL:         ttl,
				NumUses:     numUses,
				DisplayName: displayName,
				NoDefault:   noDefault,
			})
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "%-20s%s\n", "Key", "Value")
			fmt.Fprintf(w, "%-20s%s\n", "---", "-----")
			fmt.Fprintf(w, "%-20s%s\n", "token", auth.ClientToken)
			fmt.Fprintf(w, "%-20s%s\n", "token_accessor", auth.Accessor)
			fmt.Fprintf(w, "%-20s%d\n", "token_duration", auth.LeaseDuration)
			fmt.Fprintf(w, "%-20s%v\n", "token_renewable", auth.Renewable)
			fmt.Fprintf(w, "%-20s%v\n", "token_policies", auth.Policies)
			return nil
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
			var data map[string]any
			if len(args) == 1 {
				data, err = c.TokenLookup(args[0])
			} else {
				data, err = c.TokenLookupSelf()
			}
			if err != nil {
				return err
			}
			printData(cmd, data)
			return nil
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
			auth, err := c.TokenRenew(args[0], increment)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Success! Renewed token; duration=%d\n", auth.LeaseDuration)
			return nil
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
			fmt.Fprintln(cmd.OutOrStdout(), "Success! Revoked token (if it existed).")
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
			caps, err := c.CapabilitiesSelf(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%v\n", caps)
			return nil
		},
	}
}
