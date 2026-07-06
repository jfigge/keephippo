// Package audit defines the audit device interface and its file/syslog
// implementations, with HMAC-obscured sensitive fields and fail-closed
// request/response hooks.
//
// Every audited value that could carry a secret (tokens, request/response data)
// is replaced with an HMAC-SHA256 keyed by a per-server audit salt, so log lines
// are correlatable but never reveal plaintext. The Broker fans a record out to
// all enabled devices and is fail-closed: if devices are enabled and none
// accept the record, logging returns an error and the caller must fail the
// request.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

// Device is a sink for rendered (already HMAC-obscured) audit records.
type Device interface {
	Log(record map[string]any) error
	Close() error
}

// AuthView is the post-authentication identity attached to a record.
type AuthView struct {
	ClientToken string
	Accessor    string
	Policies    []string
	DisplayName string
}

// Record is the cleartext audit event built by the core; the Broker obscures
// its sensitive fields before handing it to devices.
type Record struct {
	Type        string // "request" | "response"
	Time        string
	Operation   string
	Path        string
	ClientToken string
	RemoteAddr  string
	Auth        *AuthView
	Data        map[string]any // request data (Type=request) or response data (Type=response)
	Error       string
}

// Salt HMACs sensitive strings with a keyed hash.
type Salt struct{ key []byte }

// NewSalt returns a Salt over the given key bytes.
func NewSalt(key []byte) *Salt { return &Salt{key: append([]byte(nil), key...)} }

// HMAC returns "hmac-sha256:<hex>" for input, or "" for the empty string.
func (s *Salt) HMAC(input string) string {
	if input == "" {
		return ""
	}
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(input))
	return "hmac-sha256:" + hex.EncodeToString(m.Sum(nil))
}

// Broker fans audit records out to all registered devices.
type Broker struct {
	mu      sync.RWMutex
	salt    *Salt
	devices map[string]Device // keyed by mount path (e.g. "file/")
}

// NewBroker returns a Broker using salt to obscure sensitive fields.
func NewBroker(salt *Salt) *Broker {
	return &Broker{salt: salt, devices: map[string]Device{}}
}

// Register adds (or replaces) a device at path.
func (b *Broker) Register(path string, d Device) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if old := b.devices[path]; old != nil {
		_ = old.Close()
	}
	b.devices[path] = d
}

// Deregister removes and closes the device at path.
func (b *Broker) Deregister(path string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if d := b.devices[path]; d != nil {
		_ = d.Close()
		delete(b.devices, path)
	}
}

// Paths returns the registered device paths.
func (b *Broker) Paths() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, 0, len(b.devices))
	for p := range b.devices {
		out = append(out, p)
	}
	return out
}

// Enabled reports whether any device is registered.
func (b *Broker) Enabled() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.devices) > 0
}

// Hash returns the HMAC of input (for sys/audit-hash).
func (b *Broker) Hash(input string) string { return b.salt.HMAC(input) }

// Log obscures the record and writes it to every device. It is fail-closed:
// with at least one device enabled, it returns an error unless a device accepts
// the record. With no devices enabled, auditing is a no-op.
func (b *Broker) Log(r *Record) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if len(b.devices) == 0 {
		return nil
	}
	rendered := b.render(r)
	var lastErr error
	anyOK := false
	for _, d := range b.devices {
		if err := d.Log(rendered); err != nil {
			lastErr = err
			continue
		}
		anyOK = true
	}
	if !anyOK {
		return lastErr
	}
	return nil
}

// render turns a cleartext Record into the device-facing map with all sensitive
// values HMAC-obscured.
func (b *Broker) render(r *Record) map[string]any {
	out := map[string]any{"time": r.Time, "type": r.Type}
	if r.Error != "" {
		out["error"] = r.Error
	}
	req := map[string]any{"operation": r.Operation, "path": r.Path}
	if r.ClientToken != "" {
		req["client_token"] = b.salt.HMAC(r.ClientToken)
	}
	if r.RemoteAddr != "" {
		req["remote_address"] = r.RemoteAddr
	}
	if r.Auth != nil {
		auth := map[string]any{"policies": r.Auth.Policies}
		if r.Auth.ClientToken != "" {
			auth["client_token"] = b.salt.HMAC(r.Auth.ClientToken)
		}
		if r.Auth.Accessor != "" {
			auth["accessor"] = b.salt.HMAC(r.Auth.Accessor)
		}
		if r.Auth.DisplayName != "" {
			auth["display_name"] = r.Auth.DisplayName
		}
		out["auth"] = auth
	}
	obscured := b.obscure(r.Data)
	if r.Type == "response" {
		out["request"] = req
		out["response"] = map[string]any{"data": obscured}
	} else {
		if obscured != nil {
			req["data"] = obscured
		}
		out["request"] = req
	}
	return out
}

// obscure deep-copies v, HMAC-ing every string leaf so no plaintext secret is
// written to the log.
func (b *Broker) obscure(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = b.obscure(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = b.obscure(val)
		}
		return out
	case string:
		return b.salt.HMAC(t)
	default:
		return t // numbers, bools: not secrets
	}
}
