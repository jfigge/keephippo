package core

import (
	"errors"
	"strings"
	"testing"

	"github.com/jfigge/keephippo/internal/logical"
)

type failingDevice struct{}

func (failingDevice) Log(map[string]any) error { return errors.New("audit sink is down") }
func (failingDevice) Close() error             { return nil }

// TestAuditFailClosed asserts that when an enabled audit device errors, the
// request is rejected (fail-closed), matching Vault.
func TestAuditFailClosed(t *testing.T) {
	c := unsealedCore(t)

	// With no devices, a request proceeds (here: an invalid token → 403, not 500).
	if _, err := c.HandleRequest(&logical.Request{Operation: logical.ReadOperation, Path: "sys/mounts", ClientToken: "bad"}); err == nil {
		t.Fatal("expected an auth error")
	} else {
		var ce *CodedError
		if errors.As(err, &ce) && ce.Status == 500 {
			t.Fatal("no audit device enabled, but got a 500")
		}
	}

	// Enable a failing device: now every request fails closed with 500.
	c.audit.Register("bad/", failingDevice{})
	_, err := c.HandleRequest(&logical.Request{Operation: logical.ReadOperation, Path: "sys/mounts", ClientToken: "bad"})
	var ce *CodedError
	if !errors.As(err, &ce) || ce.Status != 500 {
		t.Fatalf("expected 500 fail-closed, got %v", err)
	}
}

func TestAuditHashSetUp(t *testing.T) {
	c := unsealedCore(t)
	h := c.AuditHash("some-token")
	if !strings.HasPrefix(h, "hmac-sha256:") {
		t.Fatalf("audit hash = %q", h)
	}
	if c.AuditHash("some-token") != h {
		t.Fatal("audit hash not deterministic")
	}
}
