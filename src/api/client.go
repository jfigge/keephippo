// Package api is keephippo's thin Go client for the /v1/* HTTP API. It is used
// by the CLI and can be imported by third-party Go code.
package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
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
}

// Client talks to a keephippo (or Vault-compatible) server.
type Client struct {
	addr  string
	token string
	hc    *http.Client
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
		addr:  addr,
		token: cfg.Token,
		hc:    &http.Client{Timeout: 30 * time.Second, Transport: tr},
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

func (c *Client) do(method, path string, reqBody, out any) error {
	var body io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.addr+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("X-Vault-Token", c.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(data, &e)
		if len(e.Errors) > 0 {
			return errors.New(strings.Join(e.Errors, "; "))
		}
		return fmt.Errorf("request to %s failed: %s", path, resp.Status)
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}
