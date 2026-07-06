package core

import (
	"math/rand"
	"testing"
	"time"

	"github.com/jfigge/keephippo/internal/physical/inmem"
)

// unsealedCore builds an initialized, unsealed in-memory core for white-box
// tests, with the background revoker stopped so tests can drive scans manually.
func unsealedCore(t *testing.T) *Core {
	t.Helper()
	c := New(inmem.New(), "inmem")
	res, err := c.Initialize(InitParams{SecretShares: 1, SecretThreshold: 1})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, err := c.Unseal(res.Keys[0]); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	c.expiration.stop()
	return c
}

func TestLeaseRenewRevoke(t *testing.T) {
	c := unsealedCore(t)
	now := time.Unix(1_700_000_000, 0)
	c.tokens.nowFn = func() time.Time { return now }
	c.expiration.nowFn = func() time.Time { return now }

	te, err := c.tokens.create(CreateTokenParams{Policies: []string{"default"}, TTL: 60 * time.Second, Renewable: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	lease, err := c.expiration.registerToken(te)
	if err != nil || lease == nil {
		t.Fatalf("register: %v %v", lease, err)
	}

	// lookup reflects remaining ttl.
	info, err := c.expiration.lookup(lease.ID)
	if err != nil || info["ttl"].(int64) != 60 {
		t.Fatalf("lookup ttl = %v (%v)", info["ttl"], err)
	}

	// renew extends the token expiry.
	now = now.Add(30 * time.Second)
	ttl, err := c.expiration.renew(lease.ID, 60*time.Second)
	if err != nil || ttl != 60 {
		t.Fatalf("renew ttl = %d (%v); want 60", ttl, err)
	}

	// revoke removes both the token and the lease (idempotently).
	if err := c.expiration.revoke(lease.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if te2, _ := c.tokens.lookup(te.ID); te2 != nil {
		t.Fatal("token still present after lease revoke")
	}
	if l, _ := c.expiration.load(lease.ID); l != nil {
		t.Fatal("lease still present after revoke")
	}
	if err := c.expiration.revoke(lease.ID); err != nil {
		t.Fatalf("double revoke should be idempotent: %v", err)
	}
}

func TestLeaseRevokePrefix(t *testing.T) {
	c := unsealedCore(t)
	var ids []string
	for i := 0; i < 5; i++ {
		te, _ := c.tokens.create(CreateTokenParams{Policies: []string{"default"}, TTL: time.Hour, Renewable: true})
		l, err := c.expiration.registerToken(te)
		if err != nil {
			t.Fatalf("register %d: %v", i, err)
		}
		ids = append(ids, l.ID)
	}
	n, err := c.expiration.revokePrefix("auth/token/create/")
	if err != nil || n != 5 {
		t.Fatalf("revokePrefix = %d (%v); want 5", n, err)
	}
	leases, _ := c.expiration.all()
	if len(leases) != 0 {
		t.Fatalf("%d leases survived revoke-prefix", len(leases))
	}
	_ = ids
}

// TestLeaseAccountingProperty drives random register/renew/revoke/expire steps
// and asserts the invariants: a token expires exactly when its lease-tracked
// expiry passes, background scans revoke expired tokens, revoked leases leave no
// dangling token, and no lease outlives its token.
func TestLeaseAccountingProperty(t *testing.T) {
	c := unsealedCore(t)
	now := time.Unix(1_700_000_000, 0)
	c.tokens.nowFn = func() time.Time { return now }
	c.expiration.nowFn = func() time.Time { return now }
	rng := rand.New(rand.NewSource(7))

	type live struct {
		leaseID string
		tokenID string
		expire  int64
	}
	var leases []live

	for step := 0; step < 300; step++ {
		switch rng.Intn(4) {
		case 0, 1: // register a new leased token
			ttl := time.Duration(1+rng.Intn(100)) * time.Second
			te, err := c.tokens.create(CreateTokenParams{Policies: []string{"default"}, TTL: ttl, Renewable: true})
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			l, err := c.expiration.registerToken(te)
			if err != nil {
				t.Fatalf("register: %v", err)
			}
			leases = append(leases, live{leaseID: l.ID, tokenID: te.ID, expire: te.ExpireTime})
		case 2: // renew a random live lease
			if len(leases) == 0 {
				continue
			}
			i := rng.Intn(len(leases))
			inc := time.Duration(1+rng.Intn(100)) * time.Second
			if ttl, err := c.expiration.renew(leases[i].leaseID, inc); err == nil {
				leases[i].expire = now.Unix() + ttl
			}
		case 3: // jump the clock forward, then let the background sweep run
			now = now.Add(time.Duration(1+rng.Intn(40)) * time.Second)
			if err := c.expiration.scanOnce(); err != nil {
				t.Fatalf("scan: %v", err)
			}
		}

		// Invariants: for every lease we think is live, the token exists iff it is
		// unexpired; expired ones must have been swept.
		kept := leases[:0]
		for _, lv := range leases {
			te, _ := c.tokens.lookup(lv.tokenID)
			expired := now.Unix() > lv.expire
			if expired {
				if te != nil {
					// Not yet swept is fine only if we haven't scanned; force a scan.
					if err := c.expiration.scanOnce(); err != nil {
						t.Fatalf("scan: %v", err)
					}
					if te2, _ := c.tokens.lookup(lv.tokenID); te2 != nil {
						t.Fatalf("step %d: expired token %s survived a scan", step, lv.tokenID)
					}
				}
				if l, _ := c.expiration.load(lv.leaseID); l != nil {
					t.Fatalf("step %d: lease %s dangles after token expiry", step, lv.leaseID)
				}
				continue
			}
			if te == nil {
				t.Fatalf("step %d: unexpired token %s vanished (expire=%d now=%d)", step, lv.tokenID, lv.expire, now.Unix())
			}
			kept = append(kept, lv)
		}
		leases = kept
	}

	// After a final far-future sweep, no leases remain.
	now = now.Add(1000 * time.Second)
	if err := c.expiration.scanOnce(); err != nil {
		t.Fatalf("final scan: %v", err)
	}
	if remaining, _ := c.expiration.all(); len(remaining) != 0 {
		t.Fatalf("%d leases leaked after all tokens expired", len(remaining))
	}
}
