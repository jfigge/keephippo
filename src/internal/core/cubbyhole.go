package core

import (
	cubby "github.com/jfigge/keephippo/builtin/logical/cubbyhole"
	"github.com/jfigge/keephippo/internal/logical"
)

// setupCubbyhole registers the built-in per-token cubbyhole engine at
// cubbyhole/. It is not part of the persisted mount table. The caller holds c.mu.
func (c *Core) setupCubbyhole() error {
	view := &barrierView{barrier: c.barrier, prefix: "cubbyhole/"}
	mb := &mountedBackend{
		entry:   &MountEntry{Path: "cubbyhole/", Type: "cubbyhole", Accessor: "cubbyhole_builtin"},
		backend: cubby.New(view),
		view:    view,
	}
	c.router["cubbyhole/"] = mb
	c.cubbyhole = mb
	return nil
}

// revokeToken revokes a token and destroys its cubbyhole.
func (c *Core) revokeToken(id string) error {
	if id == "" {
		return &CodedError{Status: 400, Message: "missing token"}
	}
	if err := c.tokens.revoke(id); err != nil {
		return err
	}
	c.purgeCubbyhole(id)
	return nil
}

// purgeCubbyhole destroys a token's cubbyhole data (best-effort).
func (c *Core) purgeCubbyhole(token string) {
	if c.cubbyhole == nil {
		return
	}
	_ = cubby.Purge(c.cubbyhole.view, token)
}

// cubbyholeWrite stores data at path in the given token's cubbyhole.
func (c *Core) cubbyholeWrite(token, path string, data map[string]any) error {
	_, err := c.cubbyhole.backend.HandleRequest(&logical.Request{
		Operation:   logical.UpdateOperation,
		Path:        path,
		Data:        data,
		ClientToken: token,
		Storage:     c.cubbyhole.view,
	})
	return err
}

// cubbyholeRead reads path from the given token's cubbyhole (nil if absent).
func (c *Core) cubbyholeRead(token, path string) (map[string]any, error) {
	resp, err := c.cubbyhole.backend.HandleRequest(&logical.Request{
		Operation:   logical.ReadOperation,
		Path:        path,
		ClientToken: token,
		Storage:     c.cubbyhole.view,
	})
	if err != nil || resp == nil {
		return nil, err
	}
	return resp.Data, nil
}
