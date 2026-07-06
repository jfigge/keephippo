//go:build e2e

package e2e

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jfigge/keephippo/api"
	"github.com/jfigge/keephippo/internal/core"
	kphttp "github.com/jfigge/keephippo/internal/http"
	"github.com/jfigge/keephippo/internal/physical/file"
)

// TestLifecycleFileBackend drives init → unseal → restart → unseal over real
// HTTP against a file-backed server, and asserts ciphertext-at-rest.
func TestLifecycleFileBackend(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keephippo.db")

	// --- first boot: sealed + uninitialized ---
	be1, err := file.New(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	srv1 := httptest.NewServer(kphttp.NewServer(core.New(be1, "file")).Handler())
	cl1, _ := api.NewClient(api.Config{Address: srv1.URL})

	st, err := cl1.SealStatus()
	if err != nil {
		t.Fatalf("seal-status: %v", err)
	}
	if st.Initialized || !st.Sealed {
		t.Fatalf("fresh status = %+v; want uninitialized+sealed", st)
	}

	// Initialize with 5 shares, threshold 3.
	initRes, err := cl1.Init(5, 3)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if len(initRes.Keys) != 5 || initRes.RootToken == "" {
		t.Fatalf("init result = %+v", initRes)
	}

	srv1.Close()
	if err := be1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// --- ciphertext at rest: the root token must not appear in the raw file ---
	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read db: %v", err)
	}
	if bytes.Contains(raw, []byte(initRes.RootToken)) {
		t.Fatal("root token found in plaintext on disk; barrier is not encrypting")
	}

	// --- restart: a new server over the same file comes up sealed ---
	be2, err := file.New(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = be2.Close() }()
	srv2 := httptest.NewServer(kphttp.NewServer(core.New(be2, "file")).Handler())
	defer srv2.Close()
	cl2, _ := api.NewClient(api.Config{Address: srv2.URL})

	if st, _ = cl2.SealStatus(); !st.Initialized || !st.Sealed {
		t.Fatalf("post-restart status = %+v; want initialized+sealed", st)
	}

	// Threshold unseal: first two shares keep it sealed; the third unseals.
	for i := 0; i < 2; i++ {
		if st, err = cl2.Unseal(initRes.Keys[i]); err != nil {
			t.Fatalf("unseal %d: %v", i, err)
		}
		if !st.Sealed {
			t.Fatalf("unsealed early after %d share(s)", i+1)
		}
	}
	if st, err = cl2.Unseal(initRes.Keys[2]); err != nil {
		t.Fatalf("unseal 3: %v", err)
	}
	if st.Sealed {
		t.Fatal("still sealed after threshold shares")
	}
}
