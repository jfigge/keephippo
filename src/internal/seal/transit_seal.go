package seal

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/jfigge/keephippo/api"
)

// AutoSeal protects the root key by encrypting it with an external key manager
// (here, a remote transit engine), so the server can unseal itself on boot with
// no operator key entry.
type AutoSeal interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	Type() string
}

// TransitSeal encrypts/decrypts the root key via a remote keephippo/Vault-
// compatible transit engine.
type TransitSeal struct {
	client *api.Client
	mount  string
	key    string
}

var _ AutoSeal = (*TransitSeal)(nil)

// TransitSealConfig configures a TransitSeal.
type TransitSealConfig struct {
	Address       string
	Token         string
	MountPath     string // transit mount path (default "transit")
	KeyName       string // transit key name (default "autounseal")
	TLSSkipVerify bool
}

// NewTransitSeal builds a transit auto-seal from cfg.
func NewTransitSeal(cfg TransitSealConfig) (*TransitSeal, error) {
	if cfg.Address == "" || cfg.Token == "" {
		return nil, fmt.Errorf("transit seal: address and token are required")
	}
	mount := cfg.MountPath
	if mount == "" {
		mount = "transit"
	}
	key := cfg.KeyName
	if key == "" {
		key = "autounseal"
	}
	c, err := api.NewClient(api.Config{Address: cfg.Address, Token: cfg.Token, TLSSkipVerify: cfg.TLSSkipVerify})
	if err != nil {
		return nil, err
	}
	return &TransitSeal{client: c, mount: mount, key: key}, nil
}

// Type identifies the seal mechanism.
func (s *TransitSeal) Type() string { return "transit" }

// Encrypt returns the transit ciphertext (a vault:vN:… string) for plaintext.
func (s *TransitSeal) Encrypt(plaintext []byte) ([]byte, error) {
	resp, err := s.client.Do(http.MethodPost, "/v1/"+s.mount+"/encrypt/"+s.key,
		map[string]any{"plaintext": base64.StdEncoding.EncodeToString(plaintext)})
	if err != nil {
		return nil, fmt.Errorf("transit seal encrypt: %w", err)
	}
	ct, _ := resp.Data["ciphertext"].(string)
	if ct == "" {
		return nil, fmt.Errorf("transit seal: empty ciphertext")
	}
	return []byte(ct), nil
}

// Decrypt recovers the plaintext from a transit ciphertext.
func (s *TransitSeal) Decrypt(ciphertext []byte) ([]byte, error) {
	resp, err := s.client.Do(http.MethodPost, "/v1/"+s.mount+"/decrypt/"+s.key,
		map[string]any{"ciphertext": string(ciphertext)})
	if err != nil {
		return nil, fmt.Errorf("transit seal decrypt: %w", err)
	}
	b64, _ := resp.Data["plaintext"].(string)
	pt, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("transit seal: invalid plaintext: %w", err)
	}
	return pt, nil
}
