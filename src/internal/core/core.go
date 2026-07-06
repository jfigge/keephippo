// Package core is the request-processing heart of the server. In Phase 1 it
// owns initialization and the seal/unseal lifecycle, wiring the seal (which
// protects the root key) to the barrier (which encrypts all storage). Later
// phases add the request router, mount tables, token/policy stores, and the
// expiration manager.
package core

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jfigge/keephippo/internal/audit"
	"github.com/jfigge/keephippo/internal/barrier"
	"github.com/jfigge/keephippo/internal/physical"
	"github.com/jfigge/keephippo/internal/seal"
	"github.com/jfigge/keephippo/internal/version"
)

const (
	sealConfigPath    = "core/seal-config"     // cleartext (N, T) — not secret
	autoUnsealKeyPath = "core/auto-unseal-key" // cleartext: root key wrapped by the auto-seal
	rootKeyLength     = 32
)

var (
	// ErrAlreadyInitialized is returned when initializing an initialized core.
	ErrAlreadyInitialized = errors.New("core: already initialized")
	// ErrNotInitialized is returned when unsealing an uninitialized core.
	ErrNotInitialized = errors.New("core: not initialized")
)

// Core coordinates the physical backend, the barrier, the seal, and — once
// unsealed — the token store and the mount table / request router.
type Core struct {
	mu          sync.RWMutex
	physical    physical.Backend
	barrier     *barrier.Barrier
	seal        *seal.ShamirSeal
	autoSeal    seal.AutoSeal // optional: transit/KMS auto-unseal
	storageType string

	tokens       *tokenStore
	policies     *policyStore
	expiration   *expirationManager
	audit        *audit.Broker
	auditDevices *mountTable
	cubbyhole    *mountedBackend // built-in per-token store at cubbyhole/
	mounts       *mountTable
	authMounts   *mountTable
	router       map[string]*mountedBackend // secret mounts, keyed by "<path>/"
	authRouter   map[string]*mountedBackend // auth mounts, keyed by "auth/<path>/"
}

// New builds a sealed core over phys. storageType is reported in seal-status
// (e.g. "file" or "inmem").
func New(phys physical.Backend, storageType string) *Core {
	b := barrier.New(phys)
	ts := newTokenStore(b)
	c := &Core{
		physical:     phys,
		barrier:      b,
		seal:         seal.NewShamir(),
		storageType:  storageType,
		tokens:       ts,
		policies:     newPolicyStore(b),
		expiration:   newExpirationManager(b, ts),
		auditDevices: &mountTable{},
		mounts:       &mountTable{},
		authMounts:   &mountTable{},
		router:       make(map[string]*mountedBackend),
		authRouter:   make(map[string]*mountedBackend),
	}
	c.expiration.onRevoke = c.purgeCubbyhole
	return c
}

// SetAutoSeal configures a transit/KMS auto-seal. When set, Initialize stores
// the root key wrapped by the seal, and AutoUnseal can unseal without operator
// key entry.
func (c *Core) SetAutoSeal(s seal.AutoSeal) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.autoSeal = s
}

// InitParams configures Shamir sharing for Initialize.
type InitParams struct {
	SecretShares    int
	SecretThreshold int
}

// InitResult is returned from a successful Initialize.
type InitResult struct {
	Keys      [][]byte // unseal key shares — surface once, never stored
	RootToken string
}

// Initialized reports whether the core has been initialized.
func (c *Core) Initialized() (bool, error) {
	e, err := c.physical.Get(sealConfigPath)
	if err != nil {
		return false, err
	}
	return e != nil, nil
}

// Sealed reports whether the barrier is sealed.
func (c *Core) Sealed() bool {
	return c.barrier.Sealed()
}

// Initialize sets up storage: it generates a root key, initializes the barrier,
// splits the root key into unseal shares, persists the seal config, and creates
// a root token. The core remains SEALED afterward; unseal with the shares.
func (c *Core) Initialize(p InitParams) (*InitResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, err := c.physical.Get(sealConfigPath); err != nil {
		return nil, err
	} else if e != nil {
		return nil, ErrAlreadyInitialized
	}

	cfg := &seal.Config{Type: "shamir", SecretShares: p.SecretShares, SecretThreshold: p.SecretThreshold}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	rootKey := make([]byte, rootKeyLength)
	if _, err := rand.Read(rootKey); err != nil {
		return nil, err
	}
	defer zero(rootKey)

	if err := c.barrier.Initialize(rootKey); err != nil {
		return nil, err
	}

	shares, err := c.seal.Split(rootKey, cfg)
	if err != nil {
		return nil, err
	}

	if err := c.saveSealConfig(cfg); err != nil {
		return nil, err
	}

	// Transiently unseal the barrier to seed the root token, then re-seal so the
	// server comes up sealed and must be unsealed with the shares.
	if err := c.barrier.Unseal(rootKey); err != nil {
		return nil, err
	}
	root, err := c.tokens.create(CreateTokenParams{Policies: []string{"root"}})
	if err != nil {
		return nil, err
	}
	if err := c.policies.set("default", defaultPolicyHCL); err != nil {
		return nil, err
	}

	if c.autoSeal != nil {
		// Auto-seal: wrap the root key with the seal and store it (cleartext, but
		// KMS-encrypted), then stay unsealed — no operator key entry needed.
		wrapped, err := c.autoSeal.Encrypt(rootKey)
		if err != nil {
			return nil, err
		}
		if err := c.physical.Put(&physical.Entry{Key: autoUnsealKeyPath, Value: wrapped}); err != nil {
			return nil, err
		}
		if err := c.setupMounts(); err != nil {
			return nil, err
		}
		c.expiration.start()
	} else if err := c.barrier.Seal(); err != nil {
		return nil, err
	}

	return &InitResult{Keys: shares, RootToken: root.ID}, nil
}

// Unseal submits one unseal key share. It returns the current sealed state: the
// core stays sealed until the threshold of distinct shares is reached, at which
// point the root key is reconstructed and the barrier is unsealed.
func (c *Core) Unseal(share []byte) (sealed bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.barrier.Sealed() {
		return false, nil
	}
	cfg, err := c.loadSealConfig()
	if err != nil {
		return true, err
	}
	if cfg == nil {
		return true, ErrNotInitialized
	}

	rootKey, done, err := c.seal.SubmitShare(share, cfg.SecretThreshold)
	if err != nil {
		return true, err
	}
	if !done {
		return true, nil
	}
	defer zero(rootKey)

	if err := c.finishUnseal(rootKey); err != nil {
		return true, err
	}
	return false, nil
}

// finishUnseal opens the barrier with rootKey, instantiates mounts/backends, and
// starts the background revoker. The caller holds c.mu.
func (c *Core) finishUnseal(rootKey []byte) error {
	if err := c.barrier.Unseal(rootKey); err != nil {
		return err
	}
	if err := c.setupMounts(); err != nil {
		return err
	}
	c.expiration.start()
	return nil
}

// AutoUnseal attempts to unseal using the configured auto-seal. It returns
// (true, nil) once unsealed, (false, nil) when no auto-seal is configured or the
// core is not yet initialized, or an error if the seal source is unreachable.
func (c *Core) AutoUnseal() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.autoSeal == nil {
		return false, nil
	}
	if !c.barrier.Sealed() {
		return true, nil
	}
	e, err := c.physical.Get(autoUnsealKeyPath)
	if err != nil {
		return false, err
	}
	if e == nil {
		return false, nil // not initialized with an auto-seal yet
	}
	rootKey, err := c.autoSeal.Decrypt(e.Value)
	if err != nil {
		return false, err
	}
	defer zero(rootKey)
	if err := c.finishUnseal(rootKey); err != nil {
		return false, err
	}
	return true, nil
}

// Seal seals the barrier and discards any in-flight unseal progress.
func (c *Core) Seal() error {
	c.expiration.stop()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seal.Reset()
	return c.barrier.Seal()
}

// ResetUnseal discards any in-flight unseal progress without sealing.
func (c *Core) ResetUnseal() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seal.Reset()
}

// SealStatus is the machine-readable seal state, shaped like Vault's
// sys/seal-status response.
type SealStatus struct {
	Type        string `json:"type"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	T           int    `json:"t"`
	N           int    `json:"n"`
	Progress    int    `json:"progress"`
	Version     string `json:"version"`
	StorageType string `json:"storage_type"`
}

// SealStatus returns the current seal state.
func (c *Core) SealStatus() (*SealStatus, error) {
	st := &SealStatus{
		Type:        "shamir",
		Sealed:      c.barrier.Sealed(),
		Progress:    c.seal.Progress(),
		Version:     version.Short(),
		StorageType: c.storageType,
	}
	cfg, err := c.loadSealConfig()
	if err != nil {
		return nil, err
	}
	if cfg != nil {
		st.Initialized = true
		st.T = cfg.SecretThreshold
		st.N = cfg.SecretShares
	}
	return st, nil
}

// Health is the machine-readable health state, shaped like Vault's sys/health.
type Health struct {
	Initialized   bool   `json:"initialized"`
	Sealed        bool   `json:"sealed"`
	Standby       bool   `json:"standby"`
	ServerTimeUTC int64  `json:"server_time_utc"`
	Version       string `json:"version"`
}

// Health returns the current health state.
func (c *Core) Health() (*Health, error) {
	init, err := c.Initialized()
	if err != nil {
		return nil, err
	}
	return &Health{
		Initialized:   init,
		Sealed:        c.barrier.Sealed(),
		Standby:       false,
		ServerTimeUTC: time.Now().UTC().Unix(),
		Version:       version.Short(),
	}, nil
}

func (c *Core) saveSealConfig(cfg *seal.Config) error {
	blob, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return c.physical.Put(&physical.Entry{Key: sealConfigPath, Value: blob})
}

func (c *Core) loadSealConfig() (*seal.Config, error) {
	e, err := c.physical.Get(sealConfigPath)
	if err != nil || e == nil {
		return nil, err
	}
	var cfg seal.Config
	if err := json.Unmarshal(e.Value, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
