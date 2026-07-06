package core

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strings"

	kvengine "github.com/jfigge/keephippo/builtin/logical/kv"
	totpengine "github.com/jfigge/keephippo/builtin/logical/totp"
	transitengine "github.com/jfigge/keephippo/builtin/logical/transit"
	"github.com/jfigge/keephippo/internal/barrier"
	"github.com/jfigge/keephippo/internal/logical"
	"github.com/jfigge/keephippo/internal/physical"
)

const mountTablePath = "core/mounts"

// MountEntry describes a mounted secrets engine (also reused for auth methods).
type MountEntry struct {
	Path        string         `json:"path"`
	Type        string         `json:"type"`
	UUID        string         `json:"uuid"`
	Accessor    string         `json:"accessor"`
	Description string         `json:"description,omitempty"`
	Options     map[string]any `json:"options,omitempty"`
}

type mountTable struct {
	Entries []*MountEntry `json:"entries"`
}

type mountedBackend struct {
	entry   *MountEntry
	backend logical.Backend
	view    logical.Storage
}

// barrierView is a per-mount logical.Storage that prefixes keys and delegates
// to the encrypted barrier, isolating each mount's data.
type barrierView struct {
	barrier *barrier.Barrier
	prefix  string
}

var _ logical.Storage = (*barrierView)(nil)

func (v *barrierView) Get(key string) (*logical.StorageEntry, error) {
	e, err := v.barrier.Get(v.prefix + key)
	if err != nil || e == nil {
		return nil, err
	}
	return &logical.StorageEntry{Key: key, Value: e.Value}, nil
}

func (v *barrierView) Put(entry *logical.StorageEntry) error {
	return v.barrier.Put(&physical.Entry{Key: v.prefix + entry.Key, Value: entry.Value})
}

func (v *barrierView) Delete(key string) error {
	return v.barrier.Delete(v.prefix + key)
}

func (v *barrierView) List(prefix string) ([]string, error) {
	return v.barrier.List(v.prefix + prefix)
}

// setupMounts loads the persisted mount table and instantiates its backends.
// The caller must hold c.mu.
func (c *Core) setupMounts() error {
	mt, err := c.loadMountTable()
	if err != nil {
		return err
	}
	c.mounts = mt
	c.router = make(map[string]*mountedBackend, len(mt.Entries))
	for _, e := range mt.Entries {
		mb, err := c.newMountedBackend(e)
		if err != nil {
			return err
		}
		c.router[e.Path] = mb
	}
	if err := c.setupCubbyhole(); err != nil {
		return err
	}
	if err := c.setupAudit(); err != nil {
		return err
	}
	return c.setupAuth()
}

// TuneMount merges opts into a mount's tunable configuration.
func (c *Core) TuneMount(path string, opts map[string]any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.barrier.Sealed() {
		return &CodedError{Status: 503, Message: "keephippo is sealed"}
	}
	path = normalizeMountPath(path)
	mb, ok := c.router[path]
	if !ok {
		return &CodedError{Status: 400, Message: fmt.Sprintf("no mount at %q", path)}
	}
	if mb.entry.Options == nil {
		mb.entry.Options = map[string]any{}
	}
	for k, v := range opts {
		if k == "description" {
			if s, ok := v.(string); ok {
				mb.entry.Description = s
			}
			continue
		}
		mb.entry.Options[k] = v
	}
	return c.saveMountTable()
}

// MountConfig returns a mount's tunable configuration.
func (c *Core) MountConfig(path string) (map[string]any, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	path = normalizeMountPath(path)
	mb, ok := c.router[path]
	if !ok {
		return nil, &CodedError{Status: 404, Message: fmt.Sprintf("no mount at %q", path)}
	}
	out := map[string]any{"description": mb.entry.Description}
	for k, v := range mb.entry.Options {
		out[k] = v
	}
	return out, nil
}

func (c *Core) newMountedBackend(e *MountEntry) (*mountedBackend, error) {
	view := &barrierView{barrier: c.barrier, prefix: "logical/" + e.UUID + "/"}
	var backend logical.Backend
	switch e.Type {
	case "kv":
		if isKVv2(e.Options) {
			backend = kvengine.NewV2(view, e.Options)
		} else {
			backend = kvengine.New(view)
		}
	case "transit":
		backend = transitengine.New(view)
	case "totp":
		backend = totpengine.New(view)
	default:
		return nil, fmt.Errorf("core: unknown backend type %q", e.Type)
	}
	return &mountedBackend{entry: e, backend: backend, view: view}, nil
}

// isKVv2 reports whether mount options select KV version 2. The version arrives
// as a string ("2") from the CLI/API but may be a JSON number after a round-trip.
func isKVv2(opts map[string]any) bool {
	switch v := opts["version"].(type) {
	case string:
		return v == "2"
	case float64:
		return v == 2
	case int:
		return v == 2
	}
	return false
}

// EnableMount mounts a new secrets engine of the given type at path and
// persists the mount table through the barrier. options carries engine-specific
// configuration captured at enable time (e.g. KV's version / max_versions).
func (c *Core) EnableMount(path, typ string, options map[string]any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.barrier.Sealed() {
		return &CodedError{Status: 503, Message: "keephippo is sealed"}
	}
	path = normalizeMountPath(path)
	if path == "" {
		return &CodedError{Status: 400, Message: "mount path must not be empty"}
	}
	if _, ok := c.router[path]; ok {
		return &CodedError{Status: 400, Message: fmt.Sprintf("path %q is already in use", path)}
	}
	if typ != "kv" && typ != "transit" && typ != "totp" {
		return &CodedError{Status: 400, Message: fmt.Sprintf("unknown backend type %q", typ)}
	}

	uuid, err := newUUID()
	if err != nil {
		return err
	}
	suffix, err := randToken("")
	if err != nil {
		return err
	}
	e := &MountEntry{Path: path, Type: typ, UUID: uuid, Accessor: typ + "_" + suffix[:8], Options: options}

	prev := c.mounts.Entries
	c.mounts.Entries = append(c.mounts.Entries, e)
	if err := c.saveMountTable(); err != nil {
		c.mounts.Entries = prev
		return err
	}
	mb, err := c.newMountedBackend(e)
	if err != nil {
		c.mounts.Entries = prev
		_ = c.saveMountTable()
		return err
	}
	c.router[path] = mb
	return nil
}

// DisableMount unmounts the engine at path and clears its data.
func (c *Core) DisableMount(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.barrier.Sealed() {
		return &CodedError{Status: 503, Message: "keephippo is sealed"}
	}
	path = normalizeMountPath(path)
	mb, ok := c.router[path]
	if !ok {
		return &CodedError{Status: 400, Message: fmt.Sprintf("no mount at %q", path)}
	}

	kept := make([]*MountEntry, 0, len(c.mounts.Entries))
	for _, e := range c.mounts.Entries {
		if e.Path != path {
			kept = append(kept, e)
		}
	}
	prev := c.mounts.Entries
	c.mounts.Entries = kept
	if err := c.saveMountTable(); err != nil {
		c.mounts.Entries = prev
		return err
	}
	delete(c.router, path)
	_ = c.clearPrefix("logical/" + mb.entry.UUID + "/")
	return nil
}

// Remount moves the engine mounted at from to to, preserving its data (which is
// keyed by the mount's UUID, not its path).
func (c *Core) Remount(from, to string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.barrier.Sealed() {
		return &CodedError{Status: 503, Message: "keephippo is sealed"}
	}
	from = normalizeMountPath(from)
	to = normalizeMountPath(to)
	if to == "" {
		return &CodedError{Status: 400, Message: "destination path must not be empty"}
	}
	mb, ok := c.router[from]
	if !ok {
		return &CodedError{Status: 400, Message: fmt.Sprintf("no mount at %q", from)}
	}
	if _, exists := c.router[to]; exists {
		return &CodedError{Status: 400, Message: fmt.Sprintf("path %q is already in use", to)}
	}

	mb.entry.Path = to
	if err := c.saveMountTable(); err != nil {
		mb.entry.Path = from
		return err
	}
	delete(c.router, from)
	c.router[to] = mb
	return nil
}

// ListMounts returns a snapshot of the mount table.
func (c *Core) ListMounts() []*MountEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*MountEntry, len(c.mounts.Entries))
	copy(out, c.mounts.Entries)
	return out
}

func (c *Core) loadMountTable() (*mountTable, error) {
	e, err := c.barrier.Get(mountTablePath)
	if err != nil {
		return nil, err
	}
	mt := &mountTable{}
	if e == nil {
		return mt, nil
	}
	if err := json.Unmarshal(e.Value, mt); err != nil {
		return nil, err
	}
	return mt, nil
}

func (c *Core) saveMountTable() error {
	blob, err := json.Marshal(c.mounts)
	if err != nil {
		return err
	}
	return c.barrier.Put(&physical.Entry{Key: mountTablePath, Value: blob})
}

// clearPrefix recursively deletes every key under prefix through the barrier.
func (c *Core) clearPrefix(prefix string) error {
	children, err := c.barrier.List(prefix)
	if err != nil {
		return err
	}
	for _, ch := range children {
		full := prefix + ch
		if strings.HasSuffix(ch, "/") {
			if err := c.clearPrefix(full); err != nil {
				return err
			}
		} else if err := c.barrier.Delete(full); err != nil {
			return err
		}
	}
	return nil
}

func normalizeMountPath(p string) string {
	p = strings.Trim(p, "/")
	if p == "" {
		return ""
	}
	return p + "/"
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
