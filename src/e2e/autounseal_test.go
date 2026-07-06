//go:build e2e

package e2e

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jfigge/keephippo/internal/core"
	kphttp "github.com/jfigge/keephippo/internal/http"
	"github.com/jfigge/keephippo/internal/physical/inmem"
	"github.com/jfigge/keephippo/internal/seal"
)

// startSealSource boots an unsealed keephippo with a transit engine + an
// "autounseal" key, to act as the KMS for a transit auto-seal. The returned
// close function tears it down (simulating the seal source going away).
func startSealSource(t *testing.T) (url, token string, closeFn func()) {
	t.Helper()
	c := core.New(inmem.New(), "inmem")
	res, err := c.Initialize(core.InitParams{SecretShares: 1, SecretThreshold: 1})
	if err != nil {
		t.Fatalf("seal-source init: %v", err)
	}
	if _, err := c.Unseal(res.Keys[0]); err != nil {
		t.Fatalf("seal-source unseal: %v", err)
	}
	srv := httptest.NewServer(kphttp.NewServer(c).Handler())
	sc := mustClient(t, srv.URL, res.RootToken)
	if _, err := sc.Do(http.MethodPost, "/v1/sys/mounts/transit", map[string]any{"type": "transit"}); err != nil {
		t.Fatalf("enable transit: %v", err)
	}
	if _, err := sc.Do(http.MethodPost, "/v1/transit/keys/autounseal", map[string]any{}); err != nil {
		t.Fatalf("create seal key: %v", err)
	}
	return srv.URL, res.RootToken, func() { srv.Close(); _ = c.Seal() }
}

// TestAutoUnsealViaTransitSeal is the Phase 8 auto-unseal DoD: a core configured
// with a transit seal initializes unsealed and, after a restart, unseals itself
// with no manual key entry.
func TestAutoUnsealViaTransitSeal(t *testing.T) {
	url, token, closeSrc := startSealSource(t)
	defer closeSrc()

	autoSeal, err := seal.NewTransitSeal(seal.TransitSealConfig{
		Address: url, Token: token, MountPath: "transit", KeyName: "autounseal",
	})
	if err != nil {
		t.Fatalf("transit seal: %v", err)
	}

	// A persistent backend shared across "reboots".
	phys := inmem.New()

	c1 := core.New(phys, "inmem")
	c1.SetAutoSeal(autoSeal)
	if _, err := c1.Initialize(core.InitParams{SecretShares: 1, SecretThreshold: 1}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if c1.Sealed() {
		t.Fatal("auto-seal init should leave the core unsealed")
	}
	_ = c1.Seal() // shut down

	// Restart: a fresh core over the same storage auto-unseals from the seal source.
	c2 := core.New(phys, "inmem")
	c2.SetAutoSeal(autoSeal)
	unsealed, err := c2.AutoUnseal()
	if err != nil || !unsealed {
		t.Fatalf("auto-unseal = (%v, %v); want (true, nil)", unsealed, err)
	}
	if c2.Sealed() {
		t.Fatal("core should be unsealed after AutoUnseal")
	}
	_ = c2.Seal()
}

// TestAutoUnsealFailsWhenSealSourceGone: removing the seal source leaves the
// server sealed.
func TestAutoUnsealFailsWhenSealSourceGone(t *testing.T) {
	url, token, closeSrc := startSealSource(t)

	autoSeal, err := seal.NewTransitSeal(seal.TransitSealConfig{
		Address: url, Token: token, MountPath: "transit", KeyName: "autounseal",
	})
	if err != nil {
		t.Fatalf("transit seal: %v", err)
	}

	phys := inmem.New()
	c1 := core.New(phys, "inmem")
	c1.SetAutoSeal(autoSeal)
	if _, err := c1.Initialize(core.InitParams{SecretShares: 1, SecretThreshold: 1}); err != nil {
		t.Fatalf("init: %v", err)
	}
	_ = c1.Seal()

	// The seal source disappears.
	closeSrc()

	c2 := core.New(phys, "inmem")
	c2.SetAutoSeal(autoSeal)
	unsealed, err := c2.AutoUnseal()
	if unsealed || err == nil {
		t.Fatalf("expected auto-unseal to fail with the seal source gone; got (%v, %v)", unsealed, err)
	}
	if !c2.Sealed() {
		t.Fatal("core must remain sealed when the seal source is unreachable")
	}
}
