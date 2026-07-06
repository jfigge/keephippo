package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/jfigge/keephippo/internal/barrier"
	"github.com/jfigge/keephippo/internal/physical"
)

const tokenPrefix = "core/tokens/"

// TokenEntry is a stored token. In Phase 2 only identity and policies matter;
// TTLs, accessors-as-index, and leases arrive in later phases.
type TokenEntry struct {
	ID       string   `json:"id"`
	Accessor string   `json:"accessor"`
	Policies []string `json:"policies"`
}

// tokenStore persists tokens through the barrier. Storage keys are the SHA-256
// of the token ID (hex) so the raw token never appears as a cleartext key.
type tokenStore struct {
	barrier *barrier.Barrier
}

func newTokenStore(b *barrier.Barrier) *tokenStore {
	return &tokenStore{barrier: b}
}

func tokenStorageKey(id string) string {
	sum := sha256.Sum256([]byte(id))
	return tokenPrefix + hex.EncodeToString(sum[:])
}

// create mints and persists a new token with the given policies.
func (ts *tokenStore) create(policies []string) (*TokenEntry, error) {
	id, err := randToken("kh.")
	if err != nil {
		return nil, err
	}
	accessor, err := randToken("")
	if err != nil {
		return nil, err
	}
	te := &TokenEntry{ID: id, Accessor: accessor, Policies: policies}
	if err := ts.persist(te); err != nil {
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
	return &te, nil
}

// revoke deletes the token.
func (ts *tokenStore) revoke(id string) error {
	return ts.barrier.Delete(tokenStorageKey(id))
}

func randToken(prefix string) (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}
