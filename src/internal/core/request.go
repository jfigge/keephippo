package core

import (
	"fmt"
	"strings"
	"time"

	"github.com/jfigge/keephippo/internal/logical"
	"github.com/jfigge/keephippo/internal/policy"
)

// CodedError carries an HTTP status code alongside a message so the HTTP layer
// can translate core failures into Vault-compatible responses.
type CodedError struct {
	Status  int
	Message string
}

func (e *CodedError) Error() string { return e.Message }

// HandleRequest is the single entry point for authenticated operations. It
// authenticates the token, enforces the ACL, and dispatches to the system
// backend (sys/*), the token backend (auth/token/*), or a mounted secrets
// engine. It intentionally holds no core lock: authentication and authorization
// touch only the (independently locked) barrier, and each dispatch target
// acquires whatever lock it needs.
func (c *Core) HandleRequest(req *logical.Request) (*logical.Response, error) {
	if c.barrier.Sealed() {
		return nil, &CodedError{Status: 503, Message: "keephippo is sealed"}
	}
	// Audit the request before doing any work; fail closed if logging fails.
	if err := c.auditRequest(req); err != nil {
		return nil, err
	}
	resp, err := c.handleInner(req)
	if aerr := c.auditResponse(req, resp, err); aerr != nil {
		return nil, aerr
	}
	if err == nil && req.WrapTTL > 0 {
		return c.wrapResponse(req, resp)
	}
	return resp, err
}

// handleInner authenticates the token, enforces the ACL, and dispatches to the
// system backend, the token backend, an auth method, or a secrets engine.
func (c *Core) handleInner(req *logical.Request) (*logical.Response, error) {
	// Login fast-path: an auth method may declare some of its paths (the login
	// paths) reachable without a token. These bypass the token guard and ACL;
	// the backend verifies the credential and core mints the token.
	c.mu.RLock()
	authMB, authRel := c.matchAuth(req.Path)
	c.mu.RUnlock()
	if authMB != nil {
		if u, ok := authMB.backend.(logical.Unauthenticated); ok && u.IsUnauthenticated(req.Operation, authRel) {
			return c.handleLogin(req, authMB, authRel)
		}
	}

	if req.ClientToken == "" {
		return nil, &CodedError{Status: 400, Message: "missing client token"}
	}
	te, err := c.tokens.use(req.ClientToken)
	if err != nil {
		return nil, err
	}
	if te == nil {
		return nil, &CodedError{Status: 403, Message: "permission denied"}
	}
	if err := c.authorize(te, req.Path, req.Operation); err != nil {
		return nil, err
	}

	switch {
	case req.Path == "sys" || strings.HasPrefix(req.Path, "sys/"):
		return c.handleSystem(req, te)
	case strings.HasPrefix(req.Path, "auth/token/"):
		return c.handleTokenAuth(req, te)
	case strings.HasPrefix(req.Path, "auth/"):
		return c.dispatchAuth(req)
	case req.Path == "identity" || strings.HasPrefix(req.Path, "identity/"):
		return c.handleIdentity(req)
	default:
		return c.dispatchLogical(req)
	}
}

// handleLogin dispatches an unauthenticated login to an auth backend and mints
// the real token from the Auth block it returns. The backend supplies the
// credential-bound policies/TTL/metadata but never a ClientToken — that is
// core's to issue.
func (c *Core) handleLogin(req *logical.Request, mb *mountedBackend, rel string) (*logical.Response, error) {
	req.Path = rel
	req.Storage = mb.view
	resp, err := mb.backend.HandleRequest(req)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Auth == nil {
		return nil, &CodedError{Status: 400, Message: "login failed"}
	}
	a := resp.Auth

	// Attach the default policy (Vault does this for method-issued tokens) unless
	// the method already granted root.
	policies := a.Policies
	if !containsString(policies, "root") && !containsString(policies, "default") {
		policies = append([]string{"default"}, policies...)
	}

	// Resolve the login alias to a stable entity and merge the policies it (and
	// its groups) contribute.
	entityID, entityPolicies, err := c.resolveIdentity(mb.entry.Accessor, a.Alias)
	if err != nil {
		return nil, err
	}
	policies = append(policies, entityPolicies...)

	te, err := c.tokens.create(CreateTokenParams{
		Policies:    policies,
		TTL:         time.Duration(a.LeaseDuration) * time.Second,
		NumUses:     a.NumUses,
		DisplayName: a.DisplayName,
		Renewable:   a.Renewable,
		EntityID:    entityID,
	})
	if err != nil {
		return nil, err
	}
	if _, err := c.expiration.registerToken(te); err != nil {
		return nil, err
	}
	auth := c.authFor(te)
	auth.DisplayName = a.DisplayName
	auth.Metadata = a.Metadata
	return &logical.Response{Auth: auth}, nil
}

// authorize enforces the token's ACL against the request path and operation.
func (c *Core) authorize(te *TokenEntry, path string, op logical.Operation) error {
	acl, err := c.aclFor(te)
	if err != nil {
		return err
	}
	if acl.Root() {
		return nil
	}
	if isSelfPath(path) {
		return nil
	}

	allowed := false
	for _, cp := range requiredCaps(op) {
		if acl.Allowed(path, cp) {
			allowed = true
			break
		}
	}
	if !allowed {
		return &CodedError{Status: 403, Message: "permission denied"}
	}
	if isSudoPath(path) && !acl.HasSudo(path) {
		return &CodedError{Status: 403, Message: "permission denied"}
	}
	return nil
}

// requiredCaps maps an operation to the capabilities that would satisfy it (a
// write is allowed by either "create" or "update").
func requiredCaps(op logical.Operation) []policy.Capability {
	switch op {
	case logical.ReadOperation:
		return []policy.Capability{policy.Read}
	case logical.ListOperation:
		return []policy.Capability{policy.List}
	case logical.CreateOperation:
		return []policy.Capability{policy.Create}
	case logical.UpdateOperation:
		return []policy.Capability{policy.Update, policy.Create}
	case logical.DeleteOperation:
		return []policy.Capability{policy.Delete}
	default:
		return nil
	}
}

// isSelfPath lists endpoints a token may always use on itself.
func isSelfPath(path string) bool {
	switch path {
	case "auth/token/lookup-self", "auth/token/renew-self", "auth/token/revoke-self", "sys/capabilities-self":
		return true
	// Unwrapping/looking up a wrapping token is done by presenting that token,
	// which is itself the secret — so these bypass the ACL (matching Vault).
	case "sys/wrapping/unwrap", "sys/wrapping/lookup":
		return true
	}
	return false
}

// isSudoPath lists root-protected endpoints that additionally require sudo.
func isSudoPath(path string) bool {
	switch path {
	case "sys/seal", "sys/remount", "sys/step-down":
		return true
	}
	// Bulk lease revocation is sudo-gated (matching Vault).
	if strings.HasPrefix(path, "sys/leases/revoke-prefix/") || strings.HasPrefix(path, "sys/leases/revoke-force/") {
		return true
	}
	return false
}

func (c *Core) dispatchLogical(req *logical.Request) (*logical.Response, error) {
	c.mu.RLock()
	mb, rel := c.matchMount(req.Path)
	c.mu.RUnlock()
	if mb == nil {
		return nil, &CodedError{Status: 404, Message: fmt.Sprintf("no handler for route %q", req.Path)}
	}
	req.Path = rel
	req.Storage = mb.view
	return mb.backend.HandleRequest(req)
}

func (c *Core) dispatchAuth(req *logical.Request) (*logical.Response, error) {
	c.mu.RLock()
	mb, rel := c.matchAuth(req.Path)
	c.mu.RUnlock()
	if mb == nil {
		return nil, &CodedError{Status: 404, Message: fmt.Sprintf("no handler for route %q", req.Path)}
	}
	req.Path = rel
	req.Storage = mb.view
	return mb.backend.HandleRequest(req)
}

// matchMount finds the secret mount whose path is the longest prefix of path.
// Callers hold c.mu.
func (c *Core) matchMount(path string) (*mountedBackend, string) {
	return longestPrefixMount(c.router, path)
}

// matchAuth finds the auth mount (keyed "auth/<path>/") whose path is the
// longest prefix of path. Callers hold c.mu.
func (c *Core) matchAuth(path string) (*mountedBackend, string) {
	return longestPrefixMount(c.authRouter, path)
}

// longestPrefixMount returns the router entry whose "<path>/" key is the longest
// prefix of path, along with the request path made relative to that mount.
func longestPrefixMount(router map[string]*mountedBackend, path string) (*mountedBackend, string) {
	var best *mountedBackend
	var bestPath string
	for p, mb := range router {
		root := strings.TrimSuffix(p, "/")
		if path == root || strings.HasPrefix(path, p) {
			if best == nil || len(p) > len(bestPath) {
				best, bestPath = mb, p
			}
		}
	}
	if best == nil {
		return nil, ""
	}
	rel := strings.TrimPrefix(path, bestPath)
	if path == strings.TrimSuffix(bestPath, "/") {
		rel = ""
	}
	return best, rel
}
