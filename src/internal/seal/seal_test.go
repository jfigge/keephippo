package seal_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/jfigge/keephippo/internal/seal"
)

func rootKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestConfigValidate(t *testing.T) {
	ok := []seal.Config{{SecretShares: 1, SecretThreshold: 1}, {SecretShares: 5, SecretThreshold: 3}, {SecretShares: 3, SecretThreshold: 3}}
	for _, c := range ok {
		if err := c.Validate(); err != nil {
			t.Errorf("Validate(%+v) = %v; want nil", c, err)
		}
	}
	bad := []seal.Config{{SecretShares: 0, SecretThreshold: 0}, {SecretShares: 1, SecretThreshold: 2}, {SecretShares: 5, SecretThreshold: 1}, {SecretShares: 3, SecretThreshold: 4}}
	for _, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("Validate(%+v) = nil; want error", c)
		}
	}
}

func TestSingleShareMode(t *testing.T) {
	s := seal.NewShamir()
	root := rootKey(t)
	cfg := &seal.Config{Type: "shamir", SecretShares: 1, SecretThreshold: 1}

	shares, err := s.Split(root, cfg)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(shares) != 1 || !bytes.Equal(shares[0], root) {
		t.Fatalf("single share must equal root key")
	}

	got, done, err := s.SubmitShare(shares[0], cfg.SecretThreshold)
	if err != nil || !done || !bytes.Equal(got, root) {
		t.Fatalf("SubmitShare = %x, %v, %v; want root, true, nil", got, done, err)
	}
}

func TestShamirThreshold(t *testing.T) {
	s := seal.NewShamir()
	root := rootKey(t)
	cfg := &seal.Config{Type: "shamir", SecretShares: 5, SecretThreshold: 3}

	shares, err := s.Split(root, cfg)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("got %d shares; want 5", len(shares))
	}

	// Two shares: not enough.
	if _, done, _ := s.SubmitShare(shares[0], 3); done {
		t.Fatal("done after 1 share")
	}
	if _, done, _ := s.SubmitShare(shares[1], 3); done {
		t.Fatal("done after 2 shares")
	}
	if got := s.Progress(); got != 2 {
		t.Fatalf("progress = %d; want 2", got)
	}
	// Duplicate share does not advance progress.
	if _, done, _ := s.SubmitShare(shares[1], 3); done {
		t.Fatal("duplicate share reached threshold")
	}
	if got := s.Progress(); got != 2 {
		t.Fatalf("progress after duplicate = %d; want 2", got)
	}
	// Third distinct share reconstructs the root key.
	got, done, err := s.SubmitShare(shares[4], 3)
	if err != nil || !done || !bytes.Equal(got, root) {
		t.Fatalf("SubmitShare(3rd) = %x, %v, %v; want root, true, nil", got, done, err)
	}
	if s.Progress() != 0 {
		t.Fatal("progress not reset after unseal")
	}
}

func TestReset(t *testing.T) {
	s := seal.NewShamir()
	root := rootKey(t)
	shares, _ := s.Split(root, &seal.Config{SecretShares: 5, SecretThreshold: 3})
	_, _, _ = s.SubmitShare(shares[0], 3)
	s.Reset()
	if s.Progress() != 0 {
		t.Fatal("progress not zero after Reset")
	}
}
