package command

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

func newLoginCmd() *cobra.Command {
	var token string
	cmd := &cobra.Command{
		Use:   "login [TOKEN]",
		Short: "Authenticate with a token and store it locally",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tok := token
			if tok == "" && len(args) == 1 {
				tok = args[0]
			}
			if tok == "" {
				fmt.Fprint(cmd.OutOrStdout(), "Token: ")
				line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
				tok = strings.TrimSpace(line)
			}
			if tok == "" {
				return fmt.Errorf("a token is required")
			}

			c, err := newClientWithToken(cmd, tok)
			if err != nil {
				return err
			}
			resp, err := c.Do(http.MethodGet, "/v1/auth/token/lookup-self", nil)
			if err != nil {
				return fmt.Errorf("token verification failed: %w", err)
			}
			if err := storeToken(tok); err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) {
				fmt.Fprintln(w, "Success! You are now authenticated. The token has been stored and")
				fmt.Fprintln(w, "will be used for future commands.")
				if pol := resp.Data["policies"]; pol != nil {
					fmt.Fprintf(w, "token_policies: %v\n", pol)
				}
			})
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "The token to authenticate with")
	return cmd
}
