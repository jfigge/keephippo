//go:build e2e

package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/jfigge/keephippo/api"
)

const tokenLeasePrefix = "sys/leases/lookup/auth/token/create/"

func leaseIDs(t *testing.T, rc *api.Client) []string {
	t.Helper()
	resp, err := rc.Do("LIST", "/v1/"+tokenLeasePrefix, nil)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil
		}
		t.Fatalf("list leases: %v", err)
	}
	var out []string
	for _, k := range stringsFromAny(resp.Data["keys"]) {
		out = append(out, "auth/token/create/"+k)
	}
	return out
}

func stringsFromAny(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// TestLeaseBackgroundRevocation proves a token lease is auto-revoked by the
// background expiration manager — verified via the root client without ever
// using the expiring token, so lazy on-use expiry can't account for it.
func TestLeaseBackgroundRevocation(t *testing.T) {
	url, root := newUnsealedServer(t)
	rc := mustClient(t, url, root)

	resp, err := rc.Do(http.MethodPost, "/v1/auth/token/create",
		map[string]any{"ttl": "1s", "policies": []string{"default"}})
	if err != nil || resp.Auth == nil {
		t.Fatalf("token create: %v", err)
	}
	tok := resp.Auth.ClientToken
	if ids := leaseIDs(t, rc); len(ids) != 1 {
		t.Fatalf("expected 1 lease, got %v", ids)
	}

	// Wait for the background sweep to remove the lease (never touching tok).
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if len(leaseIDs(t, rc)) == 0 {
			// The underlying token must also be gone.
			if _, err := rc.Do(http.MethodPost, "/v1/auth/token/lookup", map[string]any{"token": tok}); err == nil {
				t.Fatal("token still valid after lease auto-revoked")
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("lease was not auto-revoked within 6s")
}

// TestLeaseRenewKeepsAlive proves sys/leases/renew extends a token past its
// original TTL (without renew it would be swept at ~1s).
func TestLeaseRenewKeepsAlive(t *testing.T) {
	url, root := newUnsealedServer(t)
	rc := mustClient(t, url, root)

	resp, err := rc.Do(http.MethodPost, "/v1/auth/token/create",
		map[string]any{"ttl": "1s", "renewable": true, "policies": []string{"default"}})
	if err != nil || resp.Auth == nil {
		t.Fatalf("token create: %v", err)
	}
	tok := resp.Auth.ClientToken

	ids := leaseIDs(t, rc)
	if len(ids) != 1 {
		t.Fatalf("expected 1 lease, got %v", ids)
	}
	if _, err := rc.Do(http.MethodPost, "/v1/sys/leases/renew",
		map[string]any{"lease_id": ids[0], "increment": "30s"}); err != nil {
		t.Fatalf("renew: %v", err)
	}

	// Past the original 1s TTL, the renewed token is still valid.
	time.Sleep(2500 * time.Millisecond)
	if _, err := rc.Do(http.MethodPost, "/v1/auth/token/lookup", map[string]any{"token": tok}); err != nil {
		t.Fatalf("renewed token was revoked early: %v", err)
	}
}

// TestLeaseRevokePrefix revokes a whole subtree of leases at once.
func TestLeaseRevokePrefix(t *testing.T) {
	url, root := newUnsealedServer(t)
	rc := mustClient(t, url, root)

	for i := 0; i < 3; i++ {
		if _, err := rc.Do(http.MethodPost, "/v1/auth/token/create",
			map[string]any{"ttl": "1h", "policies": []string{"default"}}); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	if ids := leaseIDs(t, rc); len(ids) != 3 {
		t.Fatalf("expected 3 leases, got %d", len(ids))
	}
	if _, err := rc.Do(http.MethodPut, "/v1/sys/leases/revoke-prefix/auth/token/create/", nil); err != nil {
		t.Fatalf("revoke-prefix: %v", err)
	}
	if ids := leaseIDs(t, rc); len(ids) != 0 {
		t.Fatalf("%d leases survived revoke-prefix", len(ids))
	}
}
