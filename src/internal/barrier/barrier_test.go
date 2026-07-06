package barrier_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/jfigge/keephippo/internal/barrier"
	"github.com/jfigge/keephippo/internal/physical"
	"github.com/jfigge/keephippo/internal/physical/inmem"
)

func randomRootKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, barrier.KeyLength)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestBarrierLifecycle(t *testing.T) {
	phys := inmem.New()
	b := barrier.New(phys)
	root := randomRootKey(t)

	if ok, _ := b.Initialized(); ok {
		t.Fatal("fresh barrier reports initialized")
	}
	// Sealed barrier rejects data operations.
	if err := b.Put(&physical.Entry{Key: "x", Value: []byte("y")}); err != barrier.ErrSealed {
		t.Fatalf("Put while sealed = %v; want ErrSealed", err)
	}

	if err := b.Initialize(root); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if ok, _ := b.Initialized(); !ok {
		t.Fatal("barrier not initialized after Initialize")
	}
	if err := b.Initialize(root); err != barrier.ErrAlreadyInitialized {
		t.Fatalf("second Initialize = %v; want ErrAlreadyInitialized", err)
	}

	// Wrong root key fails to unseal.
	if err := b.Unseal(randomRootKey(t)); err != barrier.ErrInvalidKey {
		t.Fatalf("Unseal(wrong) = %v; want ErrInvalidKey", err)
	}
	if !b.Sealed() {
		t.Fatal("barrier unsealed after wrong key")
	}

	// Correct key unseals.
	if err := b.Unseal(root); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if b.Sealed() {
		t.Fatal("barrier still sealed after Unseal")
	}

	// Round-trip through the barrier.
	if err := b.Put(&physical.Entry{Key: "secret/x", Value: []byte("hunter2")}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := b.Get("secret/x")
	if err != nil || got == nil || string(got.Value) != "hunter2" {
		t.Fatalf("Get = %v, %v; want hunter2", got, err)
	}

	// Seal drops the key; operations blocked again.
	if err := b.Seal(); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := b.Get("secret/x"); err != barrier.ErrSealed {
		t.Fatalf("Get after Seal = %v; want ErrSealed", err)
	}
}

func TestBarrierCiphertextAtRest(t *testing.T) {
	phys := inmem.New()
	b := barrier.New(phys)
	root := randomRootKey(t)
	if err := b.Initialize(root); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if err := b.Unseal(root); err != nil {
		t.Fatalf("Unseal: %v", err)
	}

	const canary = "TOP-SECRET-CANARY-PLAINTEXT"
	if err := b.Put(&physical.Entry{Key: "secret/canary", Value: []byte(canary)}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// The raw physical value must not contain the plaintext.
	raw, err := phys.Get("secret/canary")
	if err != nil || raw == nil {
		t.Fatalf("raw Get: %v, %v", raw, err)
	}
	if bytes.Contains(raw.Value, []byte(canary)) {
		t.Fatal("plaintext canary found in physical storage; barrier not encrypting")
	}
	// And the keyring blob must not contain the barrier/root key material path clue.
	if raw.Value[0] != 1 {
		t.Fatalf("ciphertext version = %d; want 1", raw.Value[0])
	}
}

func TestBarrierPersistsAcrossReopen(t *testing.T) {
	phys := inmem.New()
	root := randomRootKey(t)

	b1 := barrier.New(phys)
	if err := b1.Initialize(root); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if err := b1.Unseal(root); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if err := b1.Put(&physical.Entry{Key: "k", Value: []byte("v")}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// A new barrier over the same physical must unseal with the same root key.
	b2 := barrier.New(phys)
	if err := b2.Unseal(root); err != nil {
		t.Fatalf("re-Unseal: %v", err)
	}
	got, err := b2.Get("k")
	if err != nil || got == nil || string(got.Value) != "v" {
		t.Fatalf("Get after reopen = %v, %v; want v", got, err)
	}
}
