package core

import (
	"testing"
	"time"

	"github.com/jfigge/keephippo/internal/barrier"
	"github.com/jfigge/keephippo/internal/physical/inmem"
)

func unsealedBarrier(t *testing.T) *barrier.Barrier {
	t.Helper()
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
	return b
}

func TestTokenStoreCreateLookupRevoke(t *testing.T) {
	ts := newTokenStore(unsealedBarrier(t))

	te, err := ts.create(CreateTokenParams{Policies: []string{"root"}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if te.ID == "" || te.Accessor == "" {
		t.Fatalf("empty token fields: %+v", te)
	}
	if te.ExpireTime != 0 {
		t.Fatalf("root token should not expire, got ExpireTime=%d", te.ExpireTime)
	}

	got, err := ts.lookup(te.ID)
	if err != nil || got == nil || got.ID != te.ID {
		t.Fatalf("lookup = %v, %v", got, err)
	}

	if err := ts.revoke(te.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got, _ := ts.lookup(te.ID); got != nil {
		t.Fatal("token still present after revoke")
	}
}

func TestTokenTTLNumUsesRenewAccessor(t *testing.T) {
	ts := newTokenStore(unsealedBarrier(t))
	fake := time.Unix(1_000_000, 0)
	ts.nowFn = func() time.Time { return fake }

	// num_uses = 2: two uses allowed, then revoked.
	tok, err := ts.create(CreateTokenParams{Policies: []string{"p"}, TTL: time.Hour, NumUses: 2, Renewable: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if tok.ExpireTime != fake.Unix()+3600 {
		t.Fatalf("expire = %d; want %d", tok.ExpireTime, fake.Unix()+3600)
	}
	if got, _ := ts.use(tok.ID); got == nil {
		t.Fatal("use #1 rejected")
	}
	if got, _ := ts.use(tok.ID); got == nil {
		t.Fatal("use #2 rejected")
	}
	if got, _ := ts.lookup(tok.ID); got != nil {
		t.Fatal("token not revoked after num_uses spent")
	}

	// Expiry: advance the clock past the TTL.
	exp, _ := ts.create(CreateTokenParams{Policies: []string{"p"}, TTL: time.Minute})
	fake = fake.Add(2 * time.Minute)
	if got, _ := ts.use(exp.ID); got != nil {
		t.Fatal("expired token still usable")
	}

	// Renew extends expiry from now.
	rn, _ := ts.create(CreateTokenParams{Policies: []string{"p"}, TTL: time.Minute, Renewable: true})
	renewed, err := ts.renew(rn.ID, 0)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if renewed.ExpireTime != fake.Unix()+60 {
		t.Fatalf("renewed expire = %d; want %d", renewed.ExpireTime, fake.Unix()+60)
	}

	// Revoke by accessor.
	acc, _ := ts.create(CreateTokenParams{Policies: []string{"p"}, TTL: time.Hour})
	if got, _ := ts.lookupAccessor(acc.Accessor); got == nil || got.ID != acc.ID {
		t.Fatal("lookup by accessor failed")
	}
	if err := ts.revokeAccessor(acc.Accessor); err != nil {
		t.Fatalf("revokeAccessor: %v", err)
	}
	if got, _ := ts.lookup(acc.ID); got != nil {
		t.Fatal("token not revoked by accessor")
	}
}
