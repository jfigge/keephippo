// Package barrier implements the AES-256-GCM cryptographic barrier that sits
// between the core and physical storage. Every value written through the
// barrier is encrypted; nothing reaches physical storage in plaintext.
//
// Layering of keys:
//
//	root key  ──encrypts──▶  keyring{ barrier key }  ──encrypts──▶  all data
//
// The root key is held by the seal (Shamir shares or an auto-unseal KMS) and is
// supplied to Initialize/Unseal. It is used only to unwrap the keyring and is
// never persisted in the clear.
package barrier

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/jfigge/keephippo/internal/physical"
)

// KeyLength is the AES-256 key size in bytes for both the root key and the
// barrier key.
const KeyLength = 32

// keyringPath is where the (root-key-encrypted) keyring is stored in physical
// storage. It is written and read directly, never through the barrier itself.
const keyringPath = "core/keyring"

// blobVersion is the leading byte of every ciphertext produced by the barrier.
const blobVersion byte = 1

var (
	// ErrSealed is returned by data operations while the barrier is sealed.
	ErrSealed = errors.New("barrier: sealed")
	// ErrAlreadyInitialized is returned by Initialize when a keyring exists.
	ErrAlreadyInitialized = errors.New("barrier: already initialized")
	// ErrNotInitialized is returned by Unseal when no keyring exists.
	ErrNotInitialized = errors.New("barrier: not initialized")
	// ErrInvalidKey is returned by Unseal when the root key cannot unwrap the
	// keyring (i.e. the supplied key is wrong).
	ErrInvalidKey = errors.New("barrier: invalid root key")
)

// keyring holds the barrier's data-encryption key. Term is reserved for future
// key-rotation support; Phase 1 always uses term 1.
type keyring struct {
	Term       uint32 `json:"term"`
	BarrierKey []byte `json:"barrier_key"`
}

// Barrier encrypts all values before they reach the underlying physical
// backend. It is safe for concurrent use.
type Barrier struct {
	physical physical.Backend

	mu     sync.RWMutex
	sealed bool
	key    []byte      // active barrier key; nil while sealed
	aead   cipher.AEAD // built from key; nil while sealed
}

// New returns a sealed barrier over phys.
func New(phys physical.Backend) *Barrier {
	return &Barrier{physical: phys, sealed: true}
}

// Initialized reports whether a keyring already exists in physical storage.
func (b *Barrier) Initialized() (bool, error) {
	e, err := b.physical.Get(keyringPath)
	if err != nil {
		return false, err
	}
	return e != nil, nil
}

// Initialize generates a fresh barrier key, wraps it in a keyring encrypted
// with rootKey, and stores it. The barrier remains sealed; call Unseal to use
// it. rootKey must be KeyLength bytes and is not retained.
func (b *Barrier) Initialize(rootKey []byte) error {
	if len(rootKey) != KeyLength {
		return fmt.Errorf("barrier: root key must be %d bytes, got %d", KeyLength, len(rootKey))
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if e, err := b.physical.Get(keyringPath); err != nil {
		return err
	} else if e != nil {
		return ErrAlreadyInitialized
	}

	barrierKey := make([]byte, KeyLength)
	if _, err := rand.Read(barrierKey); err != nil {
		return err
	}
	defer zero(barrierKey)

	return b.persistKeyring(rootKey, &keyring{Term: 1, BarrierKey: barrierKey})
}

// Unseal unwraps the keyring with rootKey and enables data operations. A wrong
// key yields ErrInvalidKey. rootKey must be KeyLength bytes and is not retained.
func (b *Barrier) Unseal(rootKey []byte) error {
	if len(rootKey) != KeyLength {
		return fmt.Errorf("barrier: root key must be %d bytes, got %d", KeyLength, len(rootKey))
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.sealed {
		return nil
	}

	e, err := b.physical.Get(keyringPath)
	if err != nil {
		return err
	}
	if e == nil {
		return ErrNotInitialized
	}

	rootAEAD, err := newAEAD(rootKey)
	if err != nil {
		return err
	}
	plain, err := decrypt(rootAEAD, e.Value)
	if err != nil {
		return ErrInvalidKey
	}
	defer zero(plain)

	var kr keyring
	if err := json.Unmarshal(plain, &kr); err != nil {
		return ErrInvalidKey
	}
	defer zero(kr.BarrierKey)

	aead, err := newAEAD(kr.BarrierKey)
	if err != nil {
		return err
	}
	key := make([]byte, len(kr.BarrierKey))
	copy(key, kr.BarrierKey)

	b.key = key
	b.aead = aead
	b.sealed = false
	return nil
}

// Seal drops the barrier key from memory and blocks further data operations.
func (b *Barrier) Seal() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.key != nil {
		zero(b.key)
	}
	b.key = nil
	b.aead = nil
	b.sealed = true
	return nil
}

// Sealed reports whether the barrier is currently sealed.
func (b *Barrier) Sealed() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.sealed
}

// Put encrypts entry.Value and writes it to physical storage.
func (b *Barrier) Put(entry *physical.Entry) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.sealed {
		return ErrSealed
	}
	ct, err := encrypt(b.aead, entry.Value)
	if err != nil {
		return err
	}
	return b.physical.Put(&physical.Entry{Key: entry.Key, Value: ct})
}

// Get reads and decrypts the value at key, or returns (nil, nil) if absent.
func (b *Barrier) Get(key string) (*physical.Entry, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.sealed {
		return nil, ErrSealed
	}
	e, err := b.physical.Get(key)
	if err != nil || e == nil {
		return nil, err
	}
	pt, err := decrypt(b.aead, e.Value)
	if err != nil {
		return nil, fmt.Errorf("barrier: decrypt %q: %w", key, err)
	}
	return &physical.Entry{Key: key, Value: pt}, nil
}

// Delete removes key from physical storage.
func (b *Barrier) Delete(key string) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.sealed {
		return ErrSealed
	}
	return b.physical.Delete(key)
}

// List returns the immediate children under prefix. Keys are not encrypted, so
// this passes through to physical storage.
func (b *Barrier) List(prefix string) ([]string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.sealed {
		return nil, ErrSealed
	}
	return b.physical.List(prefix)
}

// persistKeyring encrypts kr with rootKey and stores it at keyringPath.
// The caller must hold b.mu.
func (b *Barrier) persistKeyring(rootKey []byte, kr *keyring) error {
	blob, err := json.Marshal(kr)
	if err != nil {
		return err
	}
	defer zero(blob)

	rootAEAD, err := newAEAD(rootKey)
	if err != nil {
		return err
	}
	ct, err := encrypt(rootAEAD, blob)
	if err != nil {
		return err
	}
	return b.physical.Put(&physical.Entry{Key: keyringPath, Value: ct})
}

// newAEAD builds an AES-256-GCM AEAD from a 32-byte key.
func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// encrypt produces [version][nonce][ciphertext+tag].
func encrypt(aead cipher.AEAD, plaintext []byte) ([]byte, error) {
	ns := aead.NonceSize()
	nonce := make([]byte, ns)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 1+ns, 1+ns+len(plaintext)+aead.Overhead())
	out[0] = blobVersion
	copy(out[1:], nonce)
	return aead.Seal(out, nonce, plaintext, nil), nil
}

// decrypt reverses encrypt, authenticating the ciphertext.
func decrypt(aead cipher.AEAD, blob []byte) ([]byte, error) {
	ns := aead.NonceSize()
	if len(blob) < 1+ns {
		return nil, errors.New("barrier: ciphertext too short")
	}
	if blob[0] != blobVersion {
		return nil, fmt.Errorf("barrier: unknown ciphertext version %d", blob[0])
	}
	nonce := blob[1 : 1+ns]
	return aead.Open(nil, nonce, blob[1+ns:], nil)
}

// zero overwrites b with zeros to limit how long key material lingers in memory.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
