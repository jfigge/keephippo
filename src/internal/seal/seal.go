// Package seal protects the root key that unlocks the barrier.
//
// The Shamir seal splits the root key into N operator key shares of which T are
// required to reconstruct it. A single-share configuration (N=T=1) is a special
// case used by -dev mode: the lone "share" is the root key itself, with no
// secret sharing. The Seal interface leaves room for an auto-unseal (transit or
// cloud-KMS) implementation in Phase 8.
package seal

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/openbao/openbao/sdk/v2/helper/shamir"
)

// Config is the persisted, non-secret seal configuration.
type Config struct {
	Type            string `json:"type"`
	SecretShares    int    `json:"secret_shares"`
	SecretThreshold int    `json:"secret_threshold"`
}

// Validate checks the share/threshold invariants (matching Vault): 1..255
// shares; with one share the threshold must be one; otherwise the threshold is
// in [2, shares].
func (c *Config) Validate() error {
	if c.SecretShares < 1 || c.SecretShares > 255 {
		return fmt.Errorf("seal: secret_shares must be 1..255, got %d", c.SecretShares)
	}
	if c.SecretShares == 1 {
		if c.SecretThreshold != 1 {
			return fmt.Errorf("seal: secret_threshold must be 1 when secret_shares is 1")
		}
		return nil
	}
	if c.SecretThreshold < 2 || c.SecretThreshold > c.SecretShares {
		return fmt.Errorf("seal: secret_threshold must be 2..%d, got %d", c.SecretShares, c.SecretThreshold)
	}
	return nil
}

// Seal abstracts how the root key is protected.
type Seal interface {
	Type() string
}

// ShamirSeal implements Seal using Shamir's Secret Sharing and tracks the
// shares accumulated during an in-flight unseal. It is safe for concurrent use.
type ShamirSeal struct {
	mu       sync.Mutex
	progress [][]byte
}

var _ Seal = (*ShamirSeal)(nil)

// NewShamir returns a Shamir seal with no unseal progress.
func NewShamir() *ShamirSeal {
	return &ShamirSeal{}
}

// Type identifies the seal mechanism.
func (s *ShamirSeal) Type() string { return "shamir" }

// Split divides rootKey into shares according to cfg. With a single share the
// share equals rootKey (no sharing). rootKey is copied, not retained.
func (s *ShamirSeal) Split(rootKey []byte, cfg *Config) ([][]byte, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.SecretShares == 1 {
		share := make([]byte, len(rootKey))
		copy(share, rootKey)
		return [][]byte{share}, nil
	}
	return shamir.Split(rootKey, cfg.SecretShares, cfg.SecretThreshold)
}

// SubmitShare adds one key share to the in-flight unseal. Duplicate shares are
// ignored. When the number of distinct shares reaches threshold, the root key
// is reconstructed and returned with done=true, and progress is reset. The
// returned root key is owned by the caller, which should zero it after use.
func (s *ShamirSeal) SubmitShare(share []byte, threshold int) (rootKey []byte, done bool, err error) {
	if len(share) == 0 {
		return nil, false, fmt.Errorf("seal: empty key share")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.progress {
		if bytes.Equal(existing, share) {
			// Already submitted; no progress but not an error.
			return nil, false, nil
		}
	}
	dup := make([]byte, len(share))
	copy(dup, share)
	s.progress = append(s.progress, dup)

	if len(s.progress) < threshold {
		return nil, false, nil
	}

	if threshold == 1 {
		// Single-share mode: the share is the root key.
		rootKey = make([]byte, len(s.progress[0]))
		copy(rootKey, s.progress[0])
	} else {
		rootKey, err = shamir.Combine(s.progress)
	}
	s.resetLocked()
	if err != nil {
		return nil, false, err
	}
	return rootKey, true, nil
}

// Progress reports how many distinct shares have been submitted.
func (s *ShamirSeal) Progress() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.progress)
}

// Reset discards any accumulated shares.
func (s *ShamirSeal) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetLocked()
}

func (s *ShamirSeal) resetLocked() {
	for _, sh := range s.progress {
		for i := range sh {
			sh[i] = 0
		}
	}
	s.progress = nil
}
