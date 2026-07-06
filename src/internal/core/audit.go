package core

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jfigge/keephippo/internal/audit"
	"github.com/jfigge/keephippo/internal/logical"
	"github.com/jfigge/keephippo/internal/physical"
)

const (
	auditSaltPath  = "core/audit-salt"
	auditTablePath = "core/audit-devices"
)

// setupAudit loads (or generates) the audit salt and instantiates the persisted
// audit devices into a broker. The caller holds c.mu.
func (c *Core) setupAudit() error {
	saltKey, err := c.loadOrCreateAuditSalt()
	if err != nil {
		return err
	}
	c.audit = audit.NewBroker(audit.NewSalt(saltKey))

	e, err := c.barrier.Get(auditTablePath)
	if err != nil {
		return err
	}
	c.auditDevices = &mountTable{}
	if e != nil {
		if err := json.Unmarshal(e.Value, c.auditDevices); err != nil {
			return err
		}
	}
	for _, m := range c.auditDevices.Entries {
		dev, err := newAuditDevice(m)
		if err != nil {
			return err
		}
		c.audit.Register(m.Path, dev)
	}
	return nil
}

func (c *Core) loadOrCreateAuditSalt() ([]byte, error) {
	e, err := c.barrier.Get(auditSaltPath)
	if err != nil {
		return nil, err
	}
	if e != nil {
		return e.Value, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := c.barrier.Put(&physical.Entry{Key: auditSaltPath, Value: key}); err != nil {
		return nil, err
	}
	return key, nil
}

// newAuditDevice constructs an audit device from a table entry.
func newAuditDevice(e *MountEntry) (audit.Device, error) {
	switch e.Type {
	case "file":
		return audit.NewFileDevice(stringOpt(e.Options, "file_path"))
	case "syslog":
		return audit.NewSyslogDevice(stringOpt(e.Options, "tag"))
	default:
		return nil, &CodedError{Status: 400, Message: fmt.Sprintf("unknown audit device type %q", e.Type)}
	}
}

func stringOpt(opts map[string]any, key string) string {
	s, _ := opts[key].(string)
	return s
}

// EnableAudit enables an audit device of the given type at path.
func (c *Core) EnableAudit(path, typ string, options map[string]any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.barrier.Sealed() {
		return &CodedError{Status: 503, Message: "keephippo is sealed"}
	}
	path = normalizeMountPath(path)
	if path == "" {
		return &CodedError{Status: 400, Message: "audit path must not be empty"}
	}
	for _, e := range c.auditDevices.Entries {
		if e.Path == path {
			return &CodedError{Status: 400, Message: fmt.Sprintf("path %q is already in use", path)}
		}
	}
	e := &MountEntry{Path: path, Type: typ, Options: options}
	dev, err := newAuditDevice(e)
	if err != nil {
		return err
	}

	prev := c.auditDevices.Entries
	c.auditDevices.Entries = append(c.auditDevices.Entries, e)
	if err := c.saveAuditTable(); err != nil {
		c.auditDevices.Entries = prev
		_ = dev.Close()
		return err
	}
	c.audit.Register(path, dev)
	return nil
}

// DisableAudit removes an audit device.
func (c *Core) DisableAudit(path string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.barrier.Sealed() {
		return &CodedError{Status: 503, Message: "keephippo is sealed"}
	}
	path = normalizeMountPath(path)
	kept := make([]*MountEntry, 0, len(c.auditDevices.Entries))
	found := false
	for _, e := range c.auditDevices.Entries {
		if e.Path == path {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return &CodedError{Status: 400, Message: fmt.Sprintf("no audit device at %q", path)}
	}
	prev := c.auditDevices.Entries
	c.auditDevices.Entries = kept
	if err := c.saveAuditTable(); err != nil {
		c.auditDevices.Entries = prev
		return err
	}
	c.audit.Deregister(path)
	return nil
}

// ListAuditDevices returns a snapshot of the enabled audit devices.
func (c *Core) ListAuditDevices() []*MountEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*MountEntry, len(c.auditDevices.Entries))
	copy(out, c.auditDevices.Entries)
	return out
}

// AuditHash returns the HMAC of input under the server audit salt.
func (c *Core) AuditHash(input string) string {
	if c.audit == nil {
		return ""
	}
	return c.audit.Hash(input)
}

func (c *Core) saveAuditTable() error {
	blob, err := json.Marshal(c.auditDevices)
	if err != nil {
		return err
	}
	return c.barrier.Put(&physical.Entry{Key: auditTablePath, Value: blob})
}

// --- request/response audit hooks (fail-closed) ---

func (c *Core) auditRequest(req *logical.Request) error {
	if c.audit == nil || !c.audit.Enabled() {
		return nil
	}
	rec := &audit.Record{
		Type:        "request",
		Time:        time.Now().UTC().Format(time.RFC3339Nano),
		Operation:   string(req.Operation),
		Path:        req.Path,
		ClientToken: req.ClientToken,
		RemoteAddr:  req.RemoteAddr,
		Data:        req.Data,
	}
	if err := c.audit.Log(rec); err != nil {
		return &CodedError{Status: 500, Message: "audit logging failed; request rejected"}
	}
	return nil
}

func (c *Core) auditResponse(req *logical.Request, resp *logical.Response, respErr error) error {
	if c.audit == nil || !c.audit.Enabled() {
		return nil
	}
	rec := &audit.Record{
		Type:        "response",
		Time:        time.Now().UTC().Format(time.RFC3339Nano),
		Operation:   string(req.Operation),
		Path:        req.Path,
		ClientToken: req.ClientToken,
		RemoteAddr:  req.RemoteAddr,
	}
	if resp != nil {
		rec.Data = resp.Data
		if resp.Auth != nil {
			rec.Auth = &audit.AuthView{
				ClientToken: resp.Auth.ClientToken,
				Accessor:    resp.Auth.Accessor,
				Policies:    resp.Auth.Policies,
				DisplayName: resp.Auth.DisplayName,
			}
		}
	}
	if respErr != nil {
		rec.Error = respErr.Error()
	}
	if err := c.audit.Log(rec); err != nil {
		return &CodedError{Status: 500, Message: "audit logging failed; request rejected"}
	}
	return nil
}
