// Package api is keephippo's thin Go client for the /v1/* HTTP API. It is used
// by the CLI and can be imported by third-party Go code.
package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Config configures a Client.
type Config struct {
	Address       string // e.g. http://127.0.0.1:8200
	Token         string // sent as X-Vault-Token
	TLSSkipVerify bool
	WrapTTL       string // when set, sent as X-Vault-Wrap-TTL (response wrapping)
}

// Client talks to a keephippo (or Vault-compatible) server.
type Client struct {
	addr    string
	token   string
	wrapTTL string
	hc      *http.Client
}

// NewClient builds a Client from cfg, defaulting the address to
// http://127.0.0.1:8200.
func NewClient(cfg Config) (*Client, error) {
	addr := strings.TrimRight(cfg.Address, "/")
	if addr == "" {
		addr = "http://127.0.0.1:8200"
	}
	tr := &http.Transport{}
	if cfg.TLSSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in via -tls-skip-verify
	}
	return &Client{
		addr:    addr,
		token:   cfg.Token,
		wrapTTL: cfg.WrapTTL,
		hc:      &http.Client{Timeout: 30 * time.Second, Transport: tr},
	}, nil
}

// Address returns the server address the client targets.
func (c *Client) Address() string { return c.addr }

// SealStatusResponse mirrors GET /v1/sys/seal-status.
type SealStatusResponse struct {
	Type        string `json:"type"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	T           int    `json:"t"`
	N           int    `json:"n"`
	Progress    int    `json:"progress"`
	Version     string `json:"version"`
	StorageType string `json:"storage_type"`
}

// InitResponse mirrors PUT /v1/sys/init.
type InitResponse struct {
	Keys       []string `json:"keys"`
	KeysBase64 []string `json:"keys_base64"`
	RootToken  string   `json:"root_token"`
}

// SealStatus returns the server's seal status.
func (c *Client) SealStatus() (*SealStatusResponse, error) {
	var out SealStatusResponse
	if err := c.do(http.MethodGet, "/v1/sys/seal-status", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Init initializes the server with the given Shamir parameters.
func (c *Client) Init(shares, threshold int) (*InitResponse, error) {
	var out InitResponse
	body := map[string]int{"secret_shares": shares, "secret_threshold": threshold}
	if err := c.do(http.MethodPut, "/v1/sys/init", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Unseal submits a single unseal key share and returns the resulting status.
func (c *Client) Unseal(key string) (*SealStatusResponse, error) {
	var out SealStatusResponse
	if err := c.do(http.MethodPut, "/v1/sys/unseal", map[string]any{"key": key}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Seal seals the server.
func (c *Client) Seal() error {
	return c.do(http.MethodPut, "/v1/sys/seal", nil, nil)
}

// Secret is a decoded logical response envelope.
type Secret struct {
	RequestID string         `json:"request_id"`
	Data      map[string]any `json:"data"`
	Warnings  []string       `json:"warnings"`
}

// Read fetches the secret at path, or (nil, nil) if it does not exist.
func (c *Client) Read(path string) (*Secret, error) {
	var out Secret
	status, err := c.doStatus(http.MethodGet, "/v1/"+path, nil, &out)
	if err != nil {
		if status == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &out, nil
}

// Write stores data at path.
func (c *Client) Write(path string, data map[string]any) error {
	return c.do(http.MethodPut, "/v1/"+path, data, nil)
}

// Delete removes the secret at path.
func (c *Client) Delete(path string) error {
	return c.do(http.MethodDelete, "/v1/"+path, nil, nil)
}

// List returns the child keys under path, or (nil, nil) if none.
func (c *Client) List(path string) (*Secret, error) {
	var out Secret
	status, err := c.doStatus("LIST", "/v1/"+path, nil, &out)
	if err != nil {
		if status == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &out, nil
}

// MountEnable mounts a secrets engine of the given type at path.
func (c *Client) MountEnable(path, typ string) error {
	return c.do(http.MethodPost, "/v1/sys/mounts/"+path, map[string]string{"type": typ}, nil)
}

// MountDisable unmounts the engine at path.
func (c *Client) MountDisable(path string) error {
	return c.do(http.MethodDelete, "/v1/sys/mounts/"+path, nil, nil)
}

// MountRemount moves the engine mounted at from to to.
func (c *Client) MountRemount(from, to string) error {
	return c.do(http.MethodPost, "/v1/sys/remount", map[string]string{"from": from, "to": to}, nil)
}

// AuthEnable enables an auth method of the given type at path.
func (c *Client) AuthEnable(path, typ string) error {
	return c.do(http.MethodPost, "/v1/sys/auth/"+path, map[string]string{"type": typ}, nil)
}

// AuthDisable disables the auth method at path.
func (c *Client) AuthDisable(path string) error {
	return c.do(http.MethodDelete, "/v1/sys/auth/"+path, nil, nil)
}

// --- policies ---

// PolicyWrite creates or updates an ACL policy from HCL source.
func (c *Client) PolicyWrite(name, rules string) error {
	return c.do(http.MethodPut, "/v1/sys/policies/acl/"+name, map[string]string{"policy": rules}, nil)
}

// PolicyRead returns an ACL policy's HCL source, or ("", nil) if absent.
func (c *Client) PolicyRead(name string) (string, error) {
	var s Secret
	status, err := c.doStatus(http.MethodGet, "/v1/sys/policies/acl/"+name, nil, &s)
	if err != nil {
		if status == http.StatusNotFound {
			return "", nil
		}
		return "", err
	}
	rules, _ := s.Data["policy"].(string)
	return rules, nil
}

// PolicyList returns the ACL policy names.
func (c *Client) PolicyList() ([]string, error) {
	var s Secret
	if err := c.do("LIST", "/v1/sys/policies/acl", nil, &s); err != nil {
		return nil, err
	}
	return stringsFromAny(s.Data["keys"]), nil
}

// PolicyDelete removes an ACL policy.
func (c *Client) PolicyDelete(name string) error {
	return c.do(http.MethodDelete, "/v1/sys/policies/acl/"+name, nil, nil)
}

// --- tokens ---

// AuthInfo is the auth block returned by token create/renew and login.
type AuthInfo struct {
	ClientToken   string   `json:"client_token"`
	Accessor      string   `json:"accessor"`
	Policies      []string `json:"policies"`
	TokenPolicies []string `json:"token_policies"`
	LeaseDuration int64    `json:"lease_duration"`
	Renewable     bool     `json:"renewable"`
}

// TokenCreateRequest configures TokenCreate.
type TokenCreateRequest struct {
	Policies    []string
	TTL         string
	NumUses     int
	DisplayName string
	NoDefault   bool
}

// TokenCreate mints a new token.
func (c *Client) TokenCreate(r TokenCreateRequest) (*AuthInfo, error) {
	body := map[string]any{}
	if len(r.Policies) > 0 {
		body["policies"] = r.Policies
	}
	if r.TTL != "" {
		body["ttl"] = r.TTL
	}
	if r.NumUses > 0 {
		body["num_uses"] = r.NumUses
	}
	if r.DisplayName != "" {
		body["display_name"] = r.DisplayName
	}
	if r.NoDefault {
		body["no_default_policy"] = true
	}
	var out struct {
		Auth *AuthInfo `json:"auth"`
	}
	if err := c.do(http.MethodPost, "/v1/auth/token/create", body, &out); err != nil {
		return nil, err
	}
	return out.Auth, nil
}

// TokenLookup looks up a token by its ID.
func (c *Client) TokenLookup(token string) (map[string]any, error) {
	var s Secret
	if err := c.do(http.MethodPost, "/v1/auth/token/lookup", map[string]string{"token": token}, &s); err != nil {
		return nil, err
	}
	return s.Data, nil
}

// TokenLookupSelf looks up the client's own token.
func (c *Client) TokenLookupSelf() (map[string]any, error) {
	var s Secret
	if err := c.do(http.MethodGet, "/v1/auth/token/lookup-self", nil, &s); err != nil {
		return nil, err
	}
	return s.Data, nil
}

// TokenRenew extends a token's TTL.
func (c *Client) TokenRenew(token, increment string) (*AuthInfo, error) {
	body := map[string]any{"token": token}
	if increment != "" {
		body["increment"] = increment
	}
	var out struct {
		Auth *AuthInfo `json:"auth"`
	}
	if err := c.do(http.MethodPost, "/v1/auth/token/renew", body, &out); err != nil {
		return nil, err
	}
	return out.Auth, nil
}

// TokenRevoke revokes a token by its ID.
func (c *Client) TokenRevoke(token string) error {
	return c.do(http.MethodPost, "/v1/auth/token/revoke", map[string]string{"token": token}, nil)
}

// CapabilitiesSelf reports the calling token's capabilities on path.
func (c *Client) CapabilitiesSelf(path string) ([]string, error) {
	var s Secret
	if err := c.do(http.MethodPost, "/v1/sys/capabilities-self", map[string]any{"paths": []string{path}}, &s); err != nil {
		return nil, err
	}
	return stringsFromAny(s.Data["capabilities"]), nil
}

func stringsFromAny(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// ListMounts returns the mount table keyed by mount path.
func (c *Client) ListMounts() (map[string]any, error) {
	var out Secret
	if err := c.do(http.MethodGet, "/v1/sys/mounts", nil, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// Response is a full API response: the raw envelope bytes (for --format=json
// passthrough) plus the parsed fields commands need.
type Response struct {
	StatusCode int
	Raw        json.RawMessage
	RequestID  string
	Data       map[string]any
	Auth       *AuthInfo
	WrapInfo   *WrapInfo
	Warnings   []string
	Errors     []string
}

// WrapInfo is the wrap_info block returned when a response is wrapped.
type WrapInfo struct {
	Token        string `json:"token"`
	Accessor     string `json:"accessor"`
	TTL          int64  `json:"ttl"`
	CreationTime string `json:"creation_time"`
	CreationPath string `json:"creation_path"`
}

// APIError is returned by Do for any HTTP status >= 400.
type APIError struct {
	Status int
	Errors []string
}

func (e *APIError) Error() string { return strings.Join(e.Errors, "; ") }

// Do performs a request and returns the full response (always non-nil on a
// successful round-trip, even for status >= 400, which also yields an
// *APIError).
func (c *Client) Do(method, path string, reqBody any) (*Response, error) {
	var body io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.addr+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("X-Vault-Token", c.token)
	}
	if c.wrapTTL != "" {
		req.Header.Set("X-Vault-Wrap-TTL", c.wrapTTL)
	}
	hr, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = hr.Body.Close() }()

	raw, _ := io.ReadAll(hr.Body)
	resp := &Response{StatusCode: hr.StatusCode, Raw: raw}
	if len(raw) > 0 {
		var env struct {
			RequestID string         `json:"request_id"`
			Data      map[string]any `json:"data"`
			Auth      *AuthInfo      `json:"auth"`
			WrapInfo  *WrapInfo      `json:"wrap_info"`
			Warnings  []string       `json:"warnings"`
			Errors    []string       `json:"errors"`
		}
		if json.Unmarshal(raw, &env) == nil {
			resp.RequestID = env.RequestID
			resp.Data = env.Data
			resp.Auth = env.Auth
			resp.WrapInfo = env.WrapInfo
			resp.Warnings = env.Warnings
			resp.Errors = env.Errors
		}
	}
	if hr.StatusCode >= 400 {
		msgs := resp.Errors
		if len(msgs) == 0 {
			msgs = []string{fmt.Sprintf("request to %s failed: %s", path, hr.Status)}
		}
		return resp, &APIError{Status: hr.StatusCode, Errors: msgs}
	}
	return resp, nil
}

func (c *Client) do(method, path string, reqBody, out any) error {
	_, err := c.doStatus(method, path, reqBody, out)
	return err
}

func (c *Client) doStatus(method, path string, reqBody, out any) (int, error) {
	resp, err := c.Do(method, path, reqBody)
	if resp == nil {
		return 0, err
	}
	if out != nil && len(resp.Raw) > 0 {
		if uerr := json.Unmarshal(resp.Raw, out); uerr != nil && err == nil {
			return resp.StatusCode, fmt.Errorf("decode response: %w", uerr)
		}
	}
	return resp.StatusCode, err
}
