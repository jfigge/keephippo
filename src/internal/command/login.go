package command

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jfigge/keephippo/api"
)

func newLoginCmd() *cobra.Command {
	var token, method, path string
	cmd := &cobra.Command{
		Use:   "login [TOKEN | K=V...]",
		Short: "Authenticate with a token or an auth method and store the token",
		Long: "Authenticate and store the resulting token locally.\n\n" +
			"With no -method, the argument (or -token) is treated as a token.\n" +
			"With -method=userpass, pass username=<u> password=<p>.\n" +
			"With -method=approle, pass role_id=<id> secret_id=<sid>.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if method != "" {
				return runMethodLogin(cmd, method, path, args)
			}
			return runTokenLogin(cmd, token, args)
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "The token to authenticate with")
	cmd.Flags().StringVar(&method, "method", "", "Auth method to log in with: userpass or approle")
	cmd.Flags().StringVar(&path, "path", "", "Mount path of the auth method (default: the method name)")
	return cmd
}

// runTokenLogin verifies a literal token and stores it (the original behaviour).
func runTokenLogin(cmd *cobra.Command, token string, args []string) error {
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
}

// runMethodLogin performs a userpass/approle login, then stores the minted token.
func runMethodLogin(cmd *cobra.Command, method, path string, args []string) error {
	if path == "" {
		path = method
	}
	fields, err := parseKV(args)
	if err != nil {
		return err
	}

	var loginPath string
	body := map[string]any{}
	switch method {
	case "userpass":
		user, _ := fields["username"].(string)
		if user == "" {
			return fmt.Errorf("userpass login requires username=<user>")
		}
		loginPath = fmt.Sprintf("/v1/auth/%s/login/%s", path, user)
		body["password"] = fields["password"]
	case "approle":
		loginPath = fmt.Sprintf("/v1/auth/%s/login", path)
		body["role_id"] = fields["role_id"]
		body["secret_id"] = fields["secret_id"]
	default:
		return fmt.Errorf("unsupported auth method %q (want userpass or approle)", method)
	}

	// Log in unauthenticated (no stored token on this request).
	c, err := newClientWithToken(cmd, "")
	if err != nil {
		return err
	}
	resp, err := c.Do(http.MethodPost, loginPath, body)
	if err != nil {
		return err
	}
	if resp.Auth == nil || resp.Auth.ClientToken == "" {
		return fmt.Errorf("login did not return a token")
	}
	if err := storeToken(resp.Auth.ClientToken); err != nil {
		return err
	}
	return emit(cmd, resp, func(w io.Writer) { loginSuccess(w, resp.Auth) })
}

func loginSuccess(w io.Writer, a *api.AuthInfo) {
	fmt.Fprintln(w, "Success! You are now authenticated. The token has been stored and")
	fmt.Fprintln(w, "will be used for future commands.")
	fmt.Fprintf(w, "%-20s%s\n", "token", a.ClientToken)
	fmt.Fprintf(w, "%-20s%d\n", "token_duration", a.LeaseDuration)
	fmt.Fprintf(w, "%-20s%v\n", "token_policies", a.Policies)
}
