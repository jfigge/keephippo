package audit

import (
	"errors"
	"strings"
	"testing"
)

func TestSaltHMACDeterministic(t *testing.T) {
	s := NewSalt([]byte("server-key"))
	a := s.HMAC("super-secret")
	b := s.HMAC("super-secret")
	if a != b {
		t.Fatalf("HMAC not deterministic: %q vs %q", a, b)
	}
	if !strings.HasPrefix(a, "hmac-sha256:") {
		t.Fatalf("unexpected HMAC prefix: %q", a)
	}
	if a == "super-secret" || strings.Contains(a, "super-secret") {
		t.Fatal("HMAC leaked plaintext")
	}
	if s.HMAC("") != "" {
		t.Fatal("empty input should HMAC to empty")
	}
	// A different key must produce a different HMAC.
	if NewSalt([]byte("other")).HMAC("super-secret") == a {
		t.Fatal("HMAC did not depend on the key")
	}
}

type failDevice struct{}

func (failDevice) Log(map[string]any) error { return errors.New("device down") }
func (failDevice) Close() error             { return nil }

type memDevice struct{ records []map[string]any }

func (m *memDevice) Log(r map[string]any) error { m.records = append(m.records, r); return nil }
func (m *memDevice) Close() error               { return nil }

func TestBrokerFailClosedAndObscure(t *testing.T) {
	b := NewBroker(NewSalt([]byte("k")))

	// No devices → auditing is a no-op (success).
	if err := b.Log(&Record{Type: "request"}); err != nil {
		t.Fatalf("no-device log should succeed: %v", err)
	}

	// One failing device and nothing else → fail-closed.
	b.Register("bad/", failDevice{})
	if err := b.Log(&Record{Type: "request"}); err == nil {
		t.Fatal("expected fail-closed error with only a failing device")
	}

	// Add a working device → at least one success means the log is accepted, and
	// the record's secret values are HMAC-obscured.
	mem := &memDevice{}
	b.Register("good/", mem)
	err := b.Log(&Record{
		Type:      "request",
		Operation: "update",
		Path:      "secret/data/app",
		Data:      map[string]any{"password": "hunter2", "nested": map[string]any{"api_key": "abc123"}},
	})
	if err != nil {
		t.Fatalf("log with a working device should succeed: %v", err)
	}
	if len(mem.records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(mem.records))
	}
	req := mem.records[0]["request"].(map[string]any)
	data := req["data"].(map[string]any)
	if data["password"] == "hunter2" {
		t.Fatal("password written in plaintext to the audit log")
	}
	if !strings.HasPrefix(data["password"].(string), "hmac-sha256:") {
		t.Fatalf("password not HMAC-obscured: %v", data["password"])
	}
	nested := data["nested"].(map[string]any)
	if nested["api_key"] == "abc123" || !strings.HasPrefix(nested["api_key"].(string), "hmac-sha256:") {
		t.Fatalf("nested secret not obscured: %v", nested["api_key"])
	}
}
