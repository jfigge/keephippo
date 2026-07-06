package core

import (
	"encoding/json"
	"fmt"

	"github.com/jfigge/keephippo/internal/physical"
)

const authTablePath = "core/auth"

// setupAuth loads the persisted auth-method table. The caller holds c.mu.
// Auth-method backends themselves land in Phase 5; Phase 4 only manages the
// table (enable/disable/list) so the CLI surface is complete.
func (c *Core) setupAuth() error {
	e, err := c.barrier.Get(authTablePath)
	if err != nil {
		return err
	}
	c.authMounts = &mountTable{}
	if e != nil {
		if err := json.Unmarshal(e.Value, c.authMounts); err != nil {
			return err
		}
	}
	return nil
}

// EnableAuth records a new auth method mounted under auth/<path>/.
func (c *Core) EnableAuth(path, typ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.barrier.Sealed() {
		return &CodedError{Status: 503, Message: "keephippo is sealed"}
	}
	path = normalizeMountPath(path)
	if path == "" {
		return &CodedError{Status: 400, Message: "auth path must not be empty"}
	}
	if path == "token/" {
		return &CodedError{Status: 400, Message: "the token auth method is built in and always enabled"}
	}
	for _, e := range c.authMounts.Entries {
		if e.Path == path {
			return &CodedError{Status: 400, Message: fmt.Sprintf("path %q is already in use", path)}
		}
	}
	uuid, err := newUUID()
	if err != nil {
		return err
	}
	suffix, err := randToken("")
	if err != nil {
		return err
	}
	c.authMounts.Entries = append(c.authMounts.Entries, &MountEntry{
		Path: path, Type: typ, UUID: uuid, Accessor: "auth_" + typ + "_" + suffix[:8],
	})
	return c.saveAuthTable()
}

// DisableAuth removes an auth method.
func (c *Core) DisableAuth(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.barrier.Sealed() {
		return &CodedError{Status: 503, Message: "keephippo is sealed"}
	}
	path = normalizeMountPath(path)
	kept := make([]*MountEntry, 0, len(c.authMounts.Entries))
	found := false
	for _, e := range c.authMounts.Entries {
		if e.Path == path {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return &CodedError{Status: 400, Message: fmt.Sprintf("no auth method at %q", path)}
	}
	c.authMounts.Entries = kept
	return c.saveAuthTable()
}

// ListAuth returns the auth methods, including the built-in token method.
func (c *Core) ListAuth() []*MountEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := []*MountEntry{{Path: "token/", Type: "token", Accessor: "auth_token_built-in"}}
	out = append(out, c.authMounts.Entries...)
	return out
}

func (c *Core) saveAuthTable() error {
	blob, err := json.Marshal(c.authMounts)
	if err != nil {
		return err
	}
	return c.barrier.Put(&physical.Entry{Key: authTablePath, Value: blob})
}
