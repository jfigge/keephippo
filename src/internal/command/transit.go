package command

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"
)

// newTransitCmd is a thin convenience wrapper over the transit engine's HTTP
// paths (equivalent to `keephippo write transit/...`), handling the base64
// encoding of plaintext for you.
func newTransitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "transit",
		Short: "Interact with the transit (encryption-as-a-service) engine",
	}
	var mount string
	cmd.PersistentFlags().StringVar(&mount, "mount", "transit", "Transit mount path")
	cmd.AddCommand(
		newTransitKeyCmd(),
		newTransitEncryptCmd(),
		newTransitDecryptCmd(),
		newTransitRewrapCmd(),
	)
	return cmd
}

func transitMount(cmd *cobra.Command) string {
	m, _ := cmd.Flags().GetString("mount")
	if m == "" {
		return "transit"
	}
	return m
}

func newTransitKeyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "key", Short: "Manage transit keys"}
	var keyType string
	create := &cobra.Command{
		Use:   "create NAME",
		Short: "Create a named key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			body := map[string]any{}
			if keyType != "" {
				body["type"] = keyType
			}
			resp, err := c.Do(http.MethodPost, "/v1/"+transitMount(cmd)+"/keys/"+args[0], body)
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) { kvTable(w, resp.Data) })
		},
	}
	create.Flags().StringVar(&keyType, "type", "", "Key type (aes256-gcm96, chacha20-poly1305, ed25519, ecdsa-p256)")
	read := &cobra.Command{
		Use:   "read NAME",
		Short: "Read a key's metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			resp, err := c.Do(http.MethodGet, "/v1/"+transitMount(cmd)+"/keys/"+args[0], nil)
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) { kvTable(w, resp.Data) })
		},
	}
	rotate := &cobra.Command{
		Use:   "rotate NAME",
		Short: "Rotate a key (add a new version)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			resp, err := c.Do(http.MethodPost, "/v1/"+transitMount(cmd)+"/keys/"+args[0]+"/rotate", nil)
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) { kvTable(w, resp.Data) })
		},
	}
	cmd.AddCommand(create, read, rotate)
	return cmd
}

func newTransitEncryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "encrypt NAME PLAINTEXT",
		Short: "Encrypt plaintext (base64-encoded for you) and print the ciphertext",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			body := map[string]any{"plaintext": base64.StdEncoding.EncodeToString([]byte(args[1]))}
			resp, err := c.Do(http.MethodPost, "/v1/"+transitMount(cmd)+"/encrypt/"+args[0], body)
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) {
				fmt.Fprintln(w, resp.Data["ciphertext"])
			})
		},
	}
}

func newTransitDecryptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "decrypt NAME CIPHERTEXT",
		Short: "Decrypt a ciphertext and print the recovered plaintext",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			resp, err := c.Do(http.MethodPost, "/v1/"+transitMount(cmd)+"/decrypt/"+args[0], map[string]any{"ciphertext": args[1]})
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) {
				enc, _ := resp.Data["plaintext"].(string)
				raw, derr := base64.StdEncoding.DecodeString(enc)
				if derr != nil {
					fmt.Fprintln(w, enc)
					return
				}
				fmt.Fprintln(w, string(raw))
			})
		},
	}
}

func newTransitRewrapCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rewrap NAME CIPHERTEXT",
		Short: "Re-encrypt a ciphertext with the key's latest version",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := newClient(cmd)
			if err != nil {
				return err
			}
			resp, err := c.Do(http.MethodPost, "/v1/"+transitMount(cmd)+"/rewrap/"+args[0], map[string]any{"ciphertext": args[1]})
			if err != nil {
				return err
			}
			return emit(cmd, resp, func(w io.Writer) {
				fmt.Fprintln(w, resp.Data["ciphertext"])
			})
		},
	}
}
