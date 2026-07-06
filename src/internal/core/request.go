package core

import (
	"fmt"
	"strings"

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
	default:
		return c.dispatchLogical(req)
	}
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
	}
	return false
}

// isSudoPath lists root-protected endpoints that additionally require sudo.
func isSudoPath(path string) bool {
	switch path {
	case "sys/seal", "sys/remount", "sys/step-down":
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

// matchMount finds the mount whose path is the longest prefix of path, and
// returns the request path relative to that mount. Callers hold c.mu.
func (c *Core) matchMount(path string) (*mountedBackend, string) {
	var best *mountedBackend
	var bestPath string
	for p, mb := range c.router {
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
