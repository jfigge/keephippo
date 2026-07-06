package core

import (
	"encoding/json"
	"fmt"

	approle "github.com/jfigge/keephippo/builtin/credential/approle"
	certauth "github.com/jfigge/keephippo/builtin/credential/cert"
	userpass "github.com/jfigge/keephippo/builtin/credential/userpass"
	"github.com/jfigge/keephippo/internal/logical"
	"github.com/jfigge/keephippo/internal/physical"
)

const authTablePath = "core/auth"

// setupAuth loads the persisted auth-method table and instantiates each method's
// backend into the auth router. The caller holds c.mu.
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
	c.authRouter = make(map[string]*mountedBackend, len(c.authMounts.Entries))
	for _, m := range c.authMounts.Entries {
		mb, err := c.newAuthBackend(m)
		if err != nil {
			return err
		}
		c.authRouter["auth/"+m.Path] = mb
	}
	return nil
}

// newAuthBackend instantiates an auth-method backend over a per-mount storage
// view. Auth data lives under the "auth/<uuid>/" barrier namespace, distinct
// from secret mounts' "logical/<uuid>/".
func (c *Core) newAuthBackend(e *MountEntry) (*mountedBackend, error) {
	view := &barrierView{barrier: c.barrier, prefix: "auth/" + e.UUID + "/"}
	var backend logical.Backend
	switch e.Type {
	case "userpass":
		backend = userpass.New(view)
	case "approle":
		backend = approle.New(view)
	case "cert":
		backend = certauth.New(view)
	default:
		return nil, fmt.Errorf("core: unknown auth method type %q", e.Type)
	}
	return &mountedBackend{entry: e, backend: backend, view: view}, nil
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
	if typ != "userpass" && typ != "approle" && typ != "cert" {
		return &CodedError{Status: 400, Message: fmt.Sprintf("unknown auth method type %q", typ)}
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
	e := &MountEntry{Path: path, Type: typ, UUID: uuid, Accessor: "auth_" + typ + "_" + suffix[:8]}

	prev := c.authMounts.Entries
	c.authMounts.Entries = append(c.authMounts.Entries, e)
	if err := c.saveAuthTable(); err != nil {
		c.authMounts.Entries = prev
		return err
	}
	mb, err := c.newAuthBackend(e)
	if err != nil {
		c.authMounts.Entries = prev
		_ = c.saveAuthTable()
		return err
	}
	c.authRouter["auth/"+path] = mb
	return nil
}

// DisableAuth removes an auth method.
func (c *Core) DisableAuth(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.barrier.Sealed() {
		return &CodedError{Status: 503, Message: "keephippo is sealed"}
	}
	path = normalizeMountPath(path)
	if path == "token/" {
		return &CodedError{Status: 400, Message: "the token auth method cannot be disabled"}
	}
	var removed *MountEntry
	kept := make([]*MountEntry, 0, len(c.authMounts.Entries))
	for _, e := range c.authMounts.Entries {
		if e.Path == path {
			removed = e
			continue
		}
		kept = append(kept, e)
	}
	if removed == nil {
		return &CodedError{Status: 400, Message: fmt.Sprintf("no auth method at %q", path)}
	}
	prev := c.authMounts.Entries
	c.authMounts.Entries = kept
	if err := c.saveAuthTable(); err != nil {
		c.authMounts.Entries = prev
		return err
	}
	delete(c.authRouter, "auth/"+path)
	_ = c.clearPrefix("auth/" + removed.UUID + "/")
	return nil
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
