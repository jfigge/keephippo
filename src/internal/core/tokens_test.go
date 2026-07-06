package core

import (
	"testing"

	"github.com/jfigge/keephippo/internal/barrier"
	"github.com/jfigge/keephippo/internal/physical/inmem"
)

func TestTokenStoreCreateLookupRevoke(t *testing.T) {
	b := barrier.New(inmem.New())
	key := make([]byte, barrier.KeyLength)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := b.Initialize(key); err != nil {
		t.Fatalf("barrier init: %v", err)
	}
	if err := b.Unseal(key); err != nil {
		t.Fatalf("barrier unseal: %v", err)
	}
	ts := newTokenStore(b)

	te, err := ts.create([]string{"root"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if te.ID == "" || te.Accessor == "" {
		t.Fatalf("empty token fields: %+v", te)
	}

	got, err := ts.lookup(te.ID)
	if err != nil || got == nil || got.ID != te.ID {
		t.Fatalf("lookup = %v, %v", got, err)
	}
	if len(got.Policies) != 1 || got.Policies[0] != "root" {
		t.Fatalf("policies = %v", got.Policies)
	}

	// The raw token id must not appear as a cleartext storage key.
	if e, _ := b.Get(tokenPrefix + te.ID); e != nil {
		t.Fatal("token stored under its plaintext id")
	}

	if err := ts.revoke(te.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got, _ := ts.lookup(te.ID); got != nil {
		t.Fatal("token still present after revoke")
	}
}
