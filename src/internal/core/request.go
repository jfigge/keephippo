package core

import (
	"fmt"
	"strings"

	"github.com/jfigge/keephippo/internal/logical"
)

// CodedError carries an HTTP status code alongside a message so the HTTP layer
// can translate core failures into Vault-compatible responses.
type CodedError struct {
	Status  int
	Message string
}

func (e *CodedError) Error() string { return e.Message }

// Authenticate verifies that token names a valid token. It returns a CodedError
// with status 400 (missing), 403 (invalid), or 503 (sealed) on failure.
func (c *Core) Authenticate(token string) (*TokenEntry, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.barrier.Sealed() {
		return nil, &CodedError{Status: 503, Message: "keephippo is sealed"}
	}
	return c.authenticate(token)
}

// authenticate assumes the caller holds c.mu and the barrier is unsealed.
func (c *Core) authenticate(token string) (*TokenEntry, error) {
	if token == "" {
		return nil, &CodedError{Status: 400, Message: "missing client token"}
	}
	te, err := c.tokens.lookup(token)
	if err != nil {
		return nil, err
	}
	if te == nil {
		return nil, &CodedError{Status: 403, Message: "permission denied"}
	}
	return te, nil
}

// HandleRequest authenticates the token, routes the request to the mounted
// backend by longest-prefix match, and returns its response. Phase 2 enforces
// only that the token is valid; capability checks arrive in Phase 3.
func (c *Core) HandleRequest(req *logical.Request) (*logical.Response, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.barrier.Sealed() {
		return nil, &CodedError{Status: 503, Message: "keephippo is sealed"}
	}
	if _, err := c.authenticate(req.ClientToken); err != nil {
		return nil, err
	}
	mb, rel := c.matchMount(req.Path)
	if mb == nil {
		return nil, &CodedError{Status: 404, Message: fmt.Sprintf("no handler for route %q", req.Path)}
	}
	req.Path = rel
	req.Storage = mb.view
	return mb.backend.HandleRequest(req)
}

// matchMount finds the mount whose path is the longest prefix of path, and
// returns the request path relative to that mount.
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
