package command

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

func newOperatorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "operator",
		Short: "Perform operator-level commands (init, unseal, seal)",
	}
	cmd.AddCommand(newOperatorInitCmd(), newOperatorUnsealCmd(), newOperatorSealCmd())
	return cmd
}

func newOperatorInitCmd() *cobra.Command {
	var shares, threshold int
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a keephippo server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			resp, err := c.Do(http.MethodPost, "/v1/sys/init", map[string]int{
				"secret_shares":    shares,
				"secret_threshold": threshold,
			})
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) {
				var out struct {
					Keys      []string `json:"keys"`
					RootToken string   `json:"root_token"`
				}
				_ = json.Unmarshal(resp.Raw, &out)
				for i, k := range out.Keys {
					fmt.Fprintf(w, "Unseal Key %d: %s\n", i+1, k)
				}
				fmt.Fprintln(w)
				fmt.Fprintf(w, "Initial Root Token: %s\n", out.RootToken)
				fmt.Fprintln(w)
				fmt.Fprintf(w, "keephippo initialized with %d key share(s) and a threshold of %d.\n", len(out.Keys), threshold)
				fmt.Fprintf(w, "Distribute the key shares securely. %d of them are required to unseal.\n", threshold)
			})
		},
	}
	cmd.Flags().IntVar(&shares, "key-shares", 5, "Number of key shares to split the root key into")
	cmd.Flags().IntVar(&threshold, "key-threshold", 3, "Number of key shares required to unseal")
	return cmd
}

func newOperatorUnsealCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unseal [KEY]",
		Short: "Submit an unseal key share",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			var key string
			if len(args) == 1 {
				key = strings.TrimSpace(args[0])
			} else {
				fmt.Fprint(cmd.OutOrStdout(), "Unseal Key: ")
				line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
				key = strings.TrimSpace(line)
			}
			if key == "" {
				return fmt.Errorf("an unseal key is required")
			}
			resp, err := c.Do(http.MethodPost, "/v1/sys/unseal", map[string]any{"key": key})
			if err != nil {
				return err
			}
			return printSealStatus(cmd, resp)
		},
	}
}

func newOperatorSealCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "seal",
		Short: "Seal the server (requires a token with sudo)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			if _, err := c.Do(http.MethodPost, "/v1/sys/seal", nil); err != nil {
				return err
			}
			success(cmd, "Success! keephippo is sealed.\n")
			return nil
		},
	}
}
