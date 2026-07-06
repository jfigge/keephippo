package command

import (
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

func newSecretsTuneCmd() *cobra.Command {
	var description, defaultLeaseTTL, maxLeaseTTL string
	cmd := &cobra.Command{
		Use:   "tune [flags] PATH",
		Short: "Tune a secrets engine's configuration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			p := strings.Trim(args[0], "/")
			body := map[string]any{}
			if description != "" {
				body["description"] = description
			}
			if defaultLeaseTTL != "" {
				body["default_lease_ttl"] = defaultLeaseTTL
			}
			if maxLeaseTTL != "" {
				body["max_lease_ttl"] = maxLeaseTTL
			}
			if _, err := c.Do(http.MethodPost, "/v1/sys/mounts/"+p+"/tune", body); err != nil {
				return err
			}
			success(cmd, "Success! Tuned the secrets engine at: %s/\n", p)
			return nil
		},
	}
	cmd.Flags().StringVar(&description, "description", "", "Human-friendly description of the mount")
	cmd.Flags().StringVar(&defaultLeaseTTL, "default-lease-ttl", "", "Default lease TTL (e.g. 1h)")
	cmd.Flags().StringVar(&maxLeaseTTL, "max-lease-ttl", "", "Maximum lease TTL (e.g. 24h)")
	return cmd
}
