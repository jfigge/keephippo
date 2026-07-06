package command

import (
	"io"
	"net/http"

	"github.com/spf13/cobra"
)

func newLeaseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lease",
		Short: "Interact with leases (lookup, renew, revoke)",
	}
	cmd.AddCommand(newLeaseLookupCmd(), newLeaseRenewCmd(), newLeaseRevokeCmd())
	return cmd
}

func newLeaseLookupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lookup LEASE_ID",
		Short: "Look up a lease's metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			resp, err := c.Do(http.MethodPost, "/v1/sys/leases/lookup", map[string]any{"lease_id": args[0]})
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) { kvTable(w, resp.Data) })
		},
	}
}

func newLeaseRenewCmd() *cobra.Command {
	var increment string
	cmd := &cobra.Command{
		Use:   "renew [-increment=DURATION] LEASE_ID",
		Short: "Renew a lease, extending its TTL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			body := map[string]any{"lease_id": args[0]}
			if increment != "" {
				body["increment"] = increment
			}
			resp, err := c.Do(http.MethodPost, "/v1/sys/leases/renew", body)
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) { kvTable(w, resp.Data) })
		},
	}
	cmd.Flags().StringVar(&increment, "increment", "", "Requested lease extension (e.g. 1h)")
	return cmd
}

func newLeaseRevokeCmd() *cobra.Command {
	var prefix bool
	cmd := &cobra.Command{
		Use:   "revoke [-prefix] LEASE_ID",
		Short: "Revoke a lease (or a whole prefix with -prefix)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			if prefix {
				if _, err := c.Do(http.MethodPut, "/v1/sys/leases/revoke-prefix/"+args[0], nil); err != nil {
					return err
				}
				success(cmd, "Success! Revoked all leases under prefix: %s\n", args[0])
				return nil
			}
			if _, err := c.Do(http.MethodPost, "/v1/sys/leases/revoke", map[string]any{"lease_id": args[0]}); err != nil {
				return err
			}
			success(cmd, "Success! Revoked lease: %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&prefix, "prefix", false, "Treat the argument as a lease-ID prefix and revoke all matches")
	return cmd
}
