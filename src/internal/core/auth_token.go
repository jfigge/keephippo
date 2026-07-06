package core

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jfigge/keephippo/internal/logical"
)

// handleTokenAuth services the auth/token/* endpoints. The token has already
// been authorized (self endpoints bypass the ACL).
func (c *Core) handleTokenAuth(req *logical.Request, caller *TokenEntry) (*logical.Response, error) {
	sub := strings.TrimPrefix(req.Path, "auth/token/")
	switch sub {
	case "create":
		return c.tokenCreate(req, caller)
	case "lookup":
		return c.tokenLookup(stringField(req.Data, "token"))
	case "lookup-self":
		return c.tokenLookup(req.ClientToken)
	case "lookup-accessor":
		return c.tokenLookupAccessor(stringField(req.Data, "accessor"))
	case "renew":
		return c.tokenRenew(stringField(req.Data, "token"), req.Data)
	case "renew-self":
		return c.tokenRenew(req.ClientToken, req.Data)
	case "revoke":
		return nil, c.tokenRevoke(stringField(req.Data, "token"))
	case "revoke-self":
		return nil, c.tokens.revoke(req.ClientToken)
	case "revoke-accessor":
		acc := stringField(req.Data, "accessor")
		if acc == "" {
			return nil, &CodedError{Status: 400, Message: "missing accessor"}
		}
		return nil, c.tokens.revokeAccessor(acc)
	default:
		return nil, &CodedError{Status: 404, Message: fmt.Sprintf("unsupported path %q", req.Path)}
	}
}

func (c *Core) tokenCreate(req *logical.Request, caller *TokenEntry) (*logical.Response, error) {
	policies := stringSliceField(req.Data, "policies")
	if !containsString(policies, "root") && !boolField(req.Data, "no_default_policy", false) {
		if !containsString(policies, "default") {
			policies = append([]string{"default"}, policies...)
		}
	}
	if containsString(policies, "root") && !caller.IsRoot() {
		return nil, &CodedError{Status: 403, Message: "root tokens can only be created by a root token"}
	}

	te, err := c.tokens.create(CreateTokenParams{
		Policies:       policies,
		TTL:            durationField(req.Data, "ttl"),
		ExplicitMaxTTL: durationField(req.Data, "explicit_max_ttl"),
		NumUses:        intField(req.Data, "num_uses"),
		DisplayName:    stringField(req.Data, "display_name"),
		Renewable:      boolField(req.Data, "renewable", true),
	})
	if err != nil {
		return nil, err
	}
	if _, err := c.expiration.registerToken(te); err != nil {
		return nil, err
	}
	return &logical.Response{Auth: c.authFor(te)}, nil
}

func (c *Core) tokenLookup(id string) (*logical.Response, error) {
	if id == "" {
		return nil, &CodedError{Status: 400, Message: "missing token"}
	}
	te, err := c.tokens.lookup(id)
	if err != nil {
		return nil, err
	}
	if te == nil {
		return nil, &CodedError{Status: 403, Message: "bad token"}
	}
	return &logical.Response{Data: c.tokenData(te)}, nil
}

func (c *Core) tokenLookupAccessor(accessor string) (*logical.Response, error) {
	if accessor == "" {
		return nil, &CodedError{Status: 400, Message: "missing accessor"}
	}
	te, err := c.tokens.lookupAccessor(accessor)
	if err != nil {
		return nil, err
	}
	if te == nil {
		return nil, &CodedError{Status: 400, Message: "invalid accessor"}
	}
	return &logical.Response{Data: c.tokenData(te)}, nil
}

func (c *Core) tokenRenew(id string, data map[string]any) (*logical.Response, error) {
	if id == "" {
		return nil, &CodedError{Status: 400, Message: "missing token"}
	}
	te, err := c.tokens.renew(id, durationField(data, "increment"))
	if err != nil {
		if errors.Is(err, errNotRenewable) {
			return nil, &CodedError{Status: 400, Message: err.Error()}
		}
		return nil, err
	}
	if te == nil {
		return nil, &CodedError{Status: 400, Message: "bad token"}
	}
	return &logical.Response{Auth: c.authFor(te)}, nil
}

func (c *Core) tokenRevoke(id string) error {
	if id == "" {
		return &CodedError{Status: 400, Message: "missing token"}
	}
	return c.tokens.revoke(id)
}

func (c *Core) authFor(te *TokenEntry) *logical.Auth {
	return &logical.Auth{
		ClientToken:   te.ID,
		Accessor:      te.Accessor,
		Policies:      te.Policies,
		TokenPolicies: te.Policies,
		LeaseDuration: c.tokens.ttlRemaining(te),
		Renewable:     te.Renewable,
	}
}

func (c *Core) tokenData(te *TokenEntry) map[string]any {
	return map[string]any{
		"id":               te.ID,
		"accessor":         te.Accessor,
		"policies":         te.Policies,
		"ttl":              c.tokens.ttlRemaining(te),
		"num_uses":         te.NumUses,
		"creation_time":    te.CreationTime,
		"expire_time":      te.ExpireTime,
		"explicit_max_ttl": te.ExplicitMaxTTL,
		"display_name":     te.DisplayName,
		"renewable":        te.Renewable,
	}
}
