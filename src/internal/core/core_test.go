package core_test

import (
	"testing"

	"github.com/jfigge/keephippo/internal/core"
	"github.com/jfigge/keephippo/internal/physical/inmem"
)

func TestInitUnsealSingleKey(t *testing.T) {
	phys := inmem.New()
	c := core.New(phys, "inmem")

	if init, _ := c.Initialized(); init {
		t.Fatal("fresh core reports initialized")
	}
	if !c.Sealed() {
		t.Fatal("fresh core not sealed")
	}

	res, err := c.Initialize(core.InitParams{SecretShares: 1, SecretThreshold: 1})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if len(res.Keys) != 1 || res.RootToken == "" {
		t.Fatalf("bad init result: keys=%d token=%q", len(res.Keys), res.RootToken)
	}
	if init, _ := c.Initialized(); !init {
		t.Fatal("core not initialized after Initialize")
	}
	if !c.Sealed() {
		t.Fatal("core should remain sealed immediately after init")
	}

	// Double init fails.
	if _, err := c.Initialize(core.InitParams{SecretShares: 1, SecretThreshold: 1}); err != core.ErrAlreadyInitialized {
		t.Fatalf("second Initialize = %v; want ErrAlreadyInitialized", err)
	}

	sealed, err := c.Unseal(res.Keys[0])
	if err != nil || sealed {
		t.Fatalf("Unseal = %v, %v; want unsealed", sealed, err)
	}
	if c.Sealed() {
		t.Fatal("core still sealed after unseal")
	}

	st, _ := c.SealStatus()
	if !st.Initialized || st.Sealed || st.T != 1 || st.N != 1 {
		t.Fatalf("seal status = %+v", st)
	}
}

func TestSealAfterRestartStaysSealed(t *testing.T) {
	phys := inmem.New()
	c1 := core.New(phys, "inmem")
	res, err := c1.Initialize(core.InitParams{SecretShares: 5, SecretThreshold: 3})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// Simulate restart: a new Core over the same storage must come up sealed.
	c2 := core.New(phys, "inmem")
	if !c2.Sealed() {
		t.Fatal("restarted core not sealed")
	}
	if init, _ := c2.Initialized(); !init {
		t.Fatal("restarted core lost initialized state")
	}

	// Two shares: still sealed.
	if sealed, _ := c2.Unseal(res.Keys[0]); !sealed {
		t.Fatal("unsealed after 1 share")
	}
	if sealed, _ := c2.Unseal(res.Keys[1]); !sealed {
		t.Fatal("unsealed after 2 shares")
	}
	// Third share: unsealed.
	sealed, err := c2.Unseal(res.Keys[3])
	if err != nil || sealed {
		t.Fatalf("Unseal(3rd) = %v, %v; want unsealed", sealed, err)
	}

	// Re-seal.
	if err := c2.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !c2.Sealed() {
		t.Fatal("not sealed after Seal")
	}
}

func TestUnsealBeforeInit(t *testing.T) {
	c := core.New(inmem.New(), "inmem")
	if _, err := c.Unseal([]byte("nope")); err != core.ErrNotInitialized {
		t.Fatalf("Unseal before init = %v; want ErrNotInitialized", err)
	}
}
