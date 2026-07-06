package core

import (
	"time"

	"github.com/jfigge/keephippo/internal/logical"
)

const (
	wrapResponseKey = "response"
	wrapInfoKey     = "wrapinfo"
	wrapPolicy      = "response-wrapping"
)

// wrapResponse replaces a response with a single-use wrapping token. The real
// payload is stored in the wrapping token's cubbyhole; the caller receives only
// wrap_info.
func (c *Core) wrapResponse(req *logical.Request, resp *logical.Response) (*logical.Response, error) {
	payload := map[string]any{}
	if resp != nil && resp.Data != nil {
		payload = resp.Data
	}
	wi, err := c.createWrapToken(req.WrapTTL, req.Path, payload)
	if err != nil {
		return nil, err
	}
	return &logical.Response{WrapInfo: wi}, nil
}

// createWrapToken mints a wrapping token, stashes the payload (+ metadata) in its
// cubbyhole, and returns the wrap_info to hand to the client.
func (c *Core) createWrapToken(ttl time.Duration, path string, payload map[string]any) (*logical.WrapInfo, error) {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	te, err := c.tokens.create(CreateTokenParams{Policies: []string{wrapPolicy}, TTL: ttl})
	if err != nil {
		return nil, err
	}
	if _, err := c.expiration.registerToken(te); err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	ttlSec := int64(ttl / time.Second)
	if err := c.cubbyholeWrite(te.ID, wrapResponseKey, payload); err != nil {
		return nil, err
	}
	if err := c.cubbyholeWrite(te.ID, wrapInfoKey, map[string]any{
		"creation_time": now, "creation_ttl": ttlSec, "creation_path": path,
	}); err != nil {
		return nil, err
	}
	return &logical.WrapInfo{
		Token:        te.ID,
		Accessor:     te.Accessor,
		TTL:          ttlSec,
		CreationTime: now,
		CreationPath: path,
	}, nil
}

// handleWrapping services sys/wrapping/* endpoints.
func (c *Core) handleWrapping(req *logical.Request, sub string) (*logical.Response, error) {
	switch sub {
	case "wrap":
		// Echo the posted data; the X-Vault-Wrap-TTL header triggers the actual
		// wrap in HandleRequest.
		return &logical.Response{Data: req.Data}, nil
	case "unwrap":
		return c.wrapUnwrap(req)
	case "lookup":
		return c.wrapLookup(req)
	case "rewrap":
		return c.wrapRewrap(req)
	default:
		return nil, &CodedError{Status: 404, Message: "unsupported wrapping path"}
	}
}

func wrapToken(req *logical.Request) string {
	if t := stringField(req.Data, "token"); t != "" {
		return t
	}
	return req.ClientToken
}

func (c *Core) wrapUnwrap(req *logical.Request) (*logical.Response, error) {
	tok := wrapToken(req)
	if tok == "" {
		return nil, &CodedError{Status: 400, Message: "missing wrapping token"}
	}
	// A valid wrapping token must still exist and be unexpired.
	te, err := c.tokens.lookup(tok)
	if err != nil {
		return nil, err
	}
	if te == nil || !containsString(te.Policies, wrapPolicy) {
		return nil, &CodedError{Status: 400, Message: "wrapping token is not valid or does not exist"}
	}
	data, err := c.cubbyholeRead(tok, wrapResponseKey)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, &CodedError{Status: 400, Message: "wrapping token is not valid or does not exist"}
	}
	// Single-use: destroy the wrapping token (and its cubbyhole) after reading.
	if err := c.revokeToken(tok); err != nil {
		return nil, err
	}
	return &logical.Response{Data: data}, nil
}

func (c *Core) wrapLookup(req *logical.Request) (*logical.Response, error) {
	tok := wrapToken(req)
	if tok == "" {
		return nil, &CodedError{Status: 400, Message: "missing wrapping token"}
	}
	info, err := c.cubbyholeRead(tok, wrapInfoKey)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, &CodedError{Status: 400, Message: "wrapping token is not valid or does not exist"}
	}
	return &logical.Response{Data: info}, nil
}

func (c *Core) wrapRewrap(req *logical.Request) (*logical.Response, error) {
	tok := wrapToken(req)
	if tok == "" {
		return nil, &CodedError{Status: 400, Message: "missing wrapping token"}
	}
	data, err := c.cubbyholeRead(tok, wrapResponseKey)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, &CodedError{Status: 400, Message: "wrapping token is not valid or does not exist"}
	}
	info, _ := c.cubbyholeRead(tok, wrapInfoKey)
	ttl := 60 * time.Second
	path := ""
	if info != nil {
		if s := intFromAny(info["creation_ttl"]); s > 0 {
			ttl = time.Duration(s) * time.Second
		}
		path, _ = info["creation_path"].(string)
	}
	if err := c.revokeToken(tok); err != nil {
		return nil, err
	}
	wi, err := c.createWrapToken(ttl, path, data)
	if err != nil {
		return nil, err
	}
	return &logical.Response{WrapInfo: wi}, nil
}

func intFromAny(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	}
	return 0
}
