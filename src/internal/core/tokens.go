package core

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jfigge/keephippo/internal/barrier"
	"github.com/jfigge/keephippo/internal/physical"
)

const (
	tokenPrefix     = "core/tokens/"
	accessorPrefix  = "core/accessors/"
	defaultTokenTTL = 32 * 24 * time.Hour // 768h, matching Vault's default
)

// errNotRenewable is returned when renewing a non-renewable token.
var errNotRenewable = errors.New("token is not renewable")

// TokenEntry is a stored token.
type TokenEntry struct {
	ID             string   `json:"id"`
	Accessor       string   `json:"accessor"`
	Policies       []string `json:"policies"`
	TTL            int64    `json:"ttl"`              // configured ttl, seconds (renew default)
	ExplicitMaxTTL int64    `json:"explicit_max_ttl"` // seconds; 0 = unlimited
	NumUses        int      `json:"num_uses"`         // 0 = unlimited
	CreationTime   int64    `json:"creation_time"`    // unix seconds
	ExpireTime     int64    `json:"expire_time"`      // unix seconds; 0 = never
	DisplayName    string   `json:"display_name"`
	Renewable      bool     `json:"renewable"`
	EntityID       string   `json:"entity_id,omitempty"`
}

// IsRoot reports whether the token carries the root policy.
func (te *TokenEntry) IsRoot() bool { return containsString(te.Policies, "root") }

// CreateTokenParams configures tokenStore.create.
type CreateTokenParams struct {
	Policies       []string
	TTL            time.Duration
	ExplicitMaxTTL time.Duration
	NumUses        int
	DisplayName    string
	Renewable      bool
	EntityID       string
}

// tokenStore persists tokens through the barrier. Storage keys are the SHA-256
// of the token ID / accessor so neither appears as a cleartext storage key.
type tokenStore struct {
	barrier *barrier.Barrier
	nowFn   func() time.Time
}

func newTokenStore(b *barrier.Barrier) *tokenStore {
	return &tokenStore{barrier: b, nowFn: time.Now}
}

func tokenStorageKey(id string) string {
	sum := sha256.Sum256([]byte(id))
	return tokenPrefix + hex.EncodeToString(sum[:])
}

func accessorStorageKey(accessor string) string {
	sum := sha256.Sum256([]byte(accessor))
	return accessorPrefix + hex.EncodeToString(sum[:])
}

// create mints and persists a new token.
func (ts *tokenStore) create(p CreateTokenParams) (*TokenEntry, error) {
	id, err := randToken("kh.")
	if err != nil {
		return nil, err
	}
	accessor, err := randToken("")
	if err != nil {
		return nil, err
	}

	now := ts.nowFn()
	ttlSec := int64(p.TTL / time.Second)
	if ttlSec == 0 && !containsString(p.Policies, "root") {
		ttlSec = int64(defaultTokenTTL / time.Second)
	}
	var expire int64
	if ttlSec > 0 {
		expire = now.Unix() + ttlSec
	}

	te := &TokenEntry{
		ID:             id,
		Accessor:       accessor,
		Policies:       dedupeStrings(p.Policies),
		TTL:            ttlSec,
		ExplicitMaxTTL: int64(p.ExplicitMaxTTL / time.Second),
		NumUses:        p.NumUses,
		CreationTime:   now.Unix(),
		ExpireTime:     expire,
		DisplayName:    p.DisplayName,
		Renewable:      p.Renewable && ttlSec > 0,
		EntityID:       p.EntityID,
	}
	if err := ts.persist(te); err != nil {
		return nil, err
	}
	if err := ts.barrier.Put(&physical.Entry{Key: accessorStorageKey(accessor), Value: []byte(id)}); err != nil {
		return nil, err
	}
	return te, nil
}

func (ts *tokenStore) persist(te *TokenEntry) error {
	blob, err := json.Marshal(te)
	if err != nil {
		return err
	}
	return ts.barrier.Put(&physical.Entry{Key: tokenStorageKey(te.ID), Value: blob})
}

// lookup returns the token entry for id, or (nil, nil) if unknown.
func (ts *tokenStore) lookup(id string) (*TokenEntry, error) {
	e, err := ts.barrier.Get(tokenStorageKey(id))
	if err != nil || e == nil {
		return nil, err
	}
	var te TokenEntry
	if err := json.Unmarshal(e.Value, &te); err != nil {
		return nil, err
	}
	// Constant-time verification of the id (defense in depth against a hash
	// collision on the storage key).
	if subtle.ConstantTimeCompare([]byte(te.ID), []byte(id)) != 1 {
		return nil, nil
	}
	return &te, nil
}

func (ts *tokenStore) lookupAccessor(accessor string) (*TokenEntry, error) {
	e, err := ts.barrier.Get(accessorStorageKey(accessor))
	if err != nil || e == nil {
		return nil, err
	}
	return ts.lookup(string(e.Value))
}

// use validates a token for a single request: it enforces expiry and num_uses,
// revoking the token when it is spent. It returns (nil, nil) for an invalid or
// expired token.
func (ts *tokenStore) use(id string) (*TokenEntry, error) {
	te, err := ts.lookup(id)
	if err != nil || te == nil {
		return nil, err
	}
	if ts.expired(te) {
		_ = ts.revoke(te.ID)
		return nil, nil
	}
	if te.NumUses > 0 {
		te.NumUses--
		if te.NumUses == 0 {
			if err := ts.revoke(te.ID); err != nil { // spent: allow this use, then revoke
				return nil, err
			}
		} else if err := ts.persist(te); err != nil {
			return nil, err
		}
	}
	return te, nil
}

// renew extends a renewable token's expiry, capped by explicit_max_ttl.
func (ts *tokenStore) renew(id string, increment time.Duration) (*TokenEntry, error) {
	te, err := ts.lookup(id)
	if err != nil || te == nil {
		return nil, err
	}
	if te.ExpireTime == 0 {
		return te, nil // non-expiring
	}
	if !te.Renewable {
		return nil, errNotRenewable
	}
	inc := increment
	if inc == 0 {
		inc = time.Duration(te.TTL) * time.Second
	}
	newExpire := ts.nowFn().Unix() + int64(inc/time.Second)
	if te.ExplicitMaxTTL > 0 {
		if maxExpire := te.CreationTime + te.ExplicitMaxTTL; newExpire > maxExpire {
			newExpire = maxExpire
		}
	}
	te.ExpireTime = newExpire
	if err := ts.persist(te); err != nil {
		return nil, err
	}
	return te, nil
}

func (ts *tokenStore) revoke(id string) error {
	if te, _ := ts.lookup(id); te != nil {
		_ = ts.barrier.Delete(accessorStorageKey(te.Accessor))
	}
	return ts.barrier.Delete(tokenStorageKey(id))
}

func (ts *tokenStore) revokeAccessor(accessor string) error {
	e, err := ts.barrier.Get(accessorStorageKey(accessor))
	if err != nil || e == nil {
		return err
	}
	return ts.revoke(string(e.Value))
}

func (ts *tokenStore) expired(te *TokenEntry) bool {
	return te.ExpireTime != 0 && ts.nowFn().Unix() > te.ExpireTime
}

// ttlRemaining returns the seconds until expiry (0 if the token never expires).
func (ts *tokenStore) ttlRemaining(te *TokenEntry) int64 {
	if te.ExpireTime == 0 {
		return 0
	}
	if r := te.ExpireTime - ts.nowFn().Unix(); r > 0 {
		return r
	}
	return 0
}

func randToken(prefix string) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func containsString(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
