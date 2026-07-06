package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/jfigge/keephippo/internal/barrier"
	"github.com/jfigge/keephippo/internal/physical"
)

const (
	leasePrefix    = "core/leases/"
	tokenLeasePath = "auth/token/create/"
	// defaultScanInterval is how often the background revoker sweeps for expired
	// leases. Small enough that expiry is timely; leases also expire lazily.
	defaultScanInterval = 1 * time.Second
)

// Lease records a time-bounded grant. Today every lease backs a token (an "auth"
// lease): the token entry remains the source of truth for expiry, so the lease
// is a persisted index that the background revoker and sys/leases/* operate on.
// Storing the TokenID lets the manager revoke/renew the underlying token.
type Lease struct {
	ID          string `json:"id"`   // e.g. auth/token/create/<random>
	Kind        string `json:"kind"` // "auth"
	TokenID     string `json:"token_id"`
	IssueTime   int64  `json:"issue_time"`
	ExpireTime  int64  `json:"expire_time"` // cached from the token; 0 = never
	TTL         int64  `json:"ttl"`         // seconds, for renew default
	MaxTTL      int64  `json:"max_ttl"`     // seconds, 0 = unlimited
	Renewable   bool   `json:"renewable"`
	LastRenewal int64  `json:"last_renewal"`
}

// expirationManager persists leases and runs a background revoker that removes
// leases (and their tokens) once expired.
type expirationManager struct {
	barrier *barrier.Barrier
	tokens  *tokenStore
	nowFn   func() time.Time
	tick    time.Duration

	mu      sync.Mutex
	stopCh  chan struct{}
	doneCh  chan struct{}
	running bool
}

func newExpirationManager(b *barrier.Barrier, ts *tokenStore) *expirationManager {
	return &expirationManager{barrier: b, tokens: ts, nowFn: time.Now, tick: defaultScanInterval}
}

func leaseStorageKey(id string) string {
	sum := sha256.Sum256([]byte(id))
	return leasePrefix + hex.EncodeToString(sum[:])
}

// registerToken records an auth lease for a token that expires. Non-expiring
// tokens (e.g. the root token) are not leased.
func (em *expirationManager) registerToken(te *TokenEntry) (*Lease, error) {
	if te.ExpireTime == 0 {
		return nil, nil
	}
	suffix, err := randToken("")
	if err != nil {
		return nil, err
	}
	l := &Lease{
		ID:         tokenLeasePath + suffix,
		Kind:       "auth",
		TokenID:    te.ID,
		IssueTime:  te.CreationTime,
		ExpireTime: te.ExpireTime,
		TTL:        te.TTL,
		MaxTTL:     te.ExplicitMaxTTL,
		Renewable:  te.Renewable,
	}
	if err := em.persist(l); err != nil {
		return nil, err
	}
	return l, nil
}

func (em *expirationManager) persist(l *Lease) error {
	blob, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return em.barrier.Put(&physical.Entry{Key: leaseStorageKey(l.ID), Value: blob})
}

func (em *expirationManager) load(id string) (*Lease, error) {
	e, err := em.barrier.Get(leaseStorageKey(id))
	if err != nil || e == nil {
		return nil, err
	}
	var l Lease
	if err := json.Unmarshal(e.Value, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// all returns every stored lease.
func (em *expirationManager) all() ([]*Lease, error) {
	names, err := em.barrier.List(leasePrefix)
	if err != nil {
		return nil, err
	}
	out := make([]*Lease, 0, len(names))
	for _, n := range names {
		if strings.HasSuffix(n, "/") {
			continue
		}
		e, err := em.barrier.Get(leasePrefix + n)
		if err != nil {
			return nil, err
		}
		if e == nil {
			continue
		}
		var l Lease
		if err := json.Unmarshal(e.Value, &l); err != nil {
			return nil, err
		}
		out = append(out, &l)
	}
	return out, nil
}

// lookup returns a lease's public details, refreshing the remaining TTL from the
// underlying token (the source of truth).
func (em *expirationManager) lookup(id string) (map[string]any, error) {
	em.mu.Lock()
	defer em.mu.Unlock()
	l, err := em.load(id)
	if err != nil {
		return nil, err
	}
	if l == nil {
		return nil, &CodedError{Status: 400, Message: "invalid lease"}
	}
	ttl := int64(0)
	if te, _ := em.tokens.lookup(l.TokenID); te != nil {
		ttl = em.tokens.ttlRemaining(te)
	}
	return map[string]any{
		"id":           l.ID,
		"issue_time":   time.Unix(l.IssueTime, 0).UTC().Format(time.RFC3339),
		"expire_time":  time.Unix(l.ExpireTime, 0).UTC().Format(time.RFC3339),
		"last_renewal": nil,
		"renewable":    l.Renewable,
		"ttl":          ttl,
	}, nil
}

// listPrefix returns lease IDs (relative to prefix) whose ID begins with prefix.
func (em *expirationManager) listPrefix(prefix string) ([]string, error) {
	em.mu.Lock()
	defer em.mu.Unlock()
	leases, err := em.all()
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var keys []string
	for _, l := range leases {
		if !strings.HasPrefix(l.ID, prefix) {
			continue
		}
		rel := strings.TrimPrefix(l.ID, prefix)
		if rel == "" {
			continue
		}
		if _, ok := seen[rel]; ok {
			continue
		}
		seen[rel] = struct{}{}
		keys = append(keys, rel)
	}
	return keys, nil
}

// renew extends a lease (and its token) by increment, capped by the lease's
// max-TTL. It returns the new remaining TTL in seconds.
func (em *expirationManager) renew(id string, increment time.Duration) (int64, error) {
	em.mu.Lock()
	defer em.mu.Unlock()
	l, err := em.load(id)
	if err != nil {
		return 0, err
	}
	if l == nil {
		return 0, &CodedError{Status: 400, Message: "invalid lease"}
	}
	if !l.Renewable {
		return 0, &CodedError{Status: 400, Message: "lease is not renewable"}
	}
	te, err := em.tokens.renew(l.TokenID, increment)
	if err != nil {
		return 0, err
	}
	if te == nil {
		_ = em.barrier.Delete(leaseStorageKey(id))
		return 0, &CodedError{Status: 400, Message: "invalid lease"}
	}
	l.ExpireTime = te.ExpireTime
	l.LastRenewal = em.nowFn().Unix()
	if err := em.persist(l); err != nil {
		return 0, err
	}
	return em.tokens.ttlRemaining(te), nil
}

// revoke revokes a lease's token and removes the lease.
func (em *expirationManager) revoke(id string) error {
	em.mu.Lock()
	defer em.mu.Unlock()
	return em.revokeLocked(id)
}

func (em *expirationManager) revokeLocked(id string) error {
	l, err := em.load(id)
	if err != nil {
		return err
	}
	if l == nil {
		return nil // already gone: idempotent
	}
	if err := em.tokens.revoke(l.TokenID); err != nil {
		return err
	}
	return em.barrier.Delete(leaseStorageKey(id))
}

// revokePrefix revokes every lease whose ID begins with prefix. It returns the
// number of leases revoked.
func (em *expirationManager) revokePrefix(prefix string) (int, error) {
	em.mu.Lock()
	defer em.mu.Unlock()
	leases, err := em.all()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, l := range leases {
		if !strings.HasPrefix(l.ID, prefix) {
			continue
		}
		if err := em.revokeLocked(l.ID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// scanOnce revokes leases whose underlying token has expired or vanished. It is
// called by the background loop and directly by tests.
func (em *expirationManager) scanOnce() error {
	em.mu.Lock()
	defer em.mu.Unlock()
	leases, err := em.all()
	if err != nil {
		return err
	}
	for _, l := range leases {
		te, err := em.tokens.lookup(l.TokenID)
		if err != nil {
			return err
		}
		if te == nil {
			// Token already revoked elsewhere: drop the dangling lease.
			_ = em.barrier.Delete(leaseStorageKey(l.ID))
			continue
		}
		if em.tokens.expired(te) {
			if err := em.revokeLocked(l.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// start launches the background revoker. Safe to call repeatedly; a no-op if
// already running.
func (em *expirationManager) start() {
	em.mu.Lock()
	if em.running {
		em.mu.Unlock()
		return
	}
	em.running = true
	em.stopCh = make(chan struct{})
	em.doneCh = make(chan struct{})
	stopCh, doneCh, tick := em.stopCh, em.doneCh, em.tick
	em.mu.Unlock()

	go func() {
		defer close(doneCh)
		t := time.NewTicker(tick)
		defer t.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-t.C:
				_ = em.scanOnce()
			}
		}
	}()
}

// stop halts the background revoker and waits for it to exit.
func (em *expirationManager) stop() {
	em.mu.Lock()
	if !em.running {
		em.mu.Unlock()
		return
	}
	em.running = false
	close(em.stopCh)
	done := em.doneCh
	em.mu.Unlock()
	<-done
}
