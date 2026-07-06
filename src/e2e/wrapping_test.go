//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/jfigge/keephippo/api"
)

// TestResponseWrappingSingleUse wraps a KV read into a single-use token, unwraps
// it exactly once, and confirms a second unwrap is denied.
func TestResponseWrappingSingleUse(t *testing.T) {
	url, root := newUnsealedServer(t)
	rc := mustClient(t, url, root)

	if err := rc.MountEnable("secret", "kv"); err != nil {
		t.Fatalf("mount: %v", err)
	}
	if err := rc.Write("secret/wrapme", map[string]any{"value": "xyz", "n": 7}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Read with X-Vault-Wrap-TTL → the response is a wrapping token, not data.
	wc, err := api.NewClient(api.Config{Address: url, Token: root, WrapTTL: "120s"})
	if err != nil {
		t.Fatalf("wrap client: %v", err)
	}
	wrapped, err := wc.Do(http.MethodGet, "/v1/secret/wrapme", nil)
	if err != nil {
		t.Fatalf("wrapped read: %v", err)
	}
	if wrapped.WrapInfo == nil || wrapped.WrapInfo.Token == "" {
		t.Fatalf("no wrap_info returned: %+v", wrapped)
	}
	if wrapped.Data["value"] == "xyz" {
		t.Fatal("wrapped response leaked the underlying data")
	}
	wt := wrapped.WrapInfo.Token

	// Lookup does not consume the wrap.
	lc := mustClient(t, url, wt)
	if _, err := lc.Do(http.MethodPost, "/v1/sys/wrapping/lookup", nil); err != nil {
		t.Fatalf("wrap lookup: %v", err)
	}

	// First unwrap returns the original data.
	un, err := lc.Do(http.MethodPost, "/v1/sys/wrapping/unwrap", nil)
	if err != nil {
		t.Fatalf("first unwrap: %v", err)
	}
	if un.Data["value"] != "xyz" {
		t.Fatalf("unwrapped data = %v; want value=xyz", un.Data)
	}

	// Second unwrap must fail (single-use); the wrapping token is now revoked.
	if _, err := lc.Do(http.MethodPost, "/v1/sys/wrapping/unwrap", nil); err == nil {
		t.Fatal("second unwrap should have failed")
	}
}

// TestWrappingWrapUnwrapArbitrary wraps arbitrary posted data via
// sys/wrapping/wrap and unwraps it.
func TestWrappingWrapUnwrapArbitrary(t *testing.T) {
	url, root := newUnsealedServer(t)

	wc, err := api.NewClient(api.Config{Address: url, Token: root, WrapTTL: "60s"})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	wrapped, err := wc.Do(http.MethodPost, "/v1/sys/wrapping/wrap", map[string]any{"foo": "bar"})
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if wrapped.WrapInfo == nil {
		t.Fatalf("no wrap_info: %+v", wrapped)
	}

	uc := mustClient(t, url, wrapped.WrapInfo.Token)
	un, err := uc.Do(http.MethodPost, "/v1/sys/wrapping/unwrap", nil)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if un.Data["foo"] != "bar" {
		t.Fatalf("unwrapped = %v; want foo=bar", un.Data)
	}
}
