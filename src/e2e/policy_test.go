//go:build e2e

package e2e

import (
	"testing"

	"github.com/jfigge/keephippo/api"
)

func sliceContains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

// TestScopedPolicyOverHTTP drives the Phase 3 DoD over real HTTP: a scoped
// policy grants read on one path, denies writes there and access elsewhere,
// while the root token retains full access.
func TestScopedPolicyOverHTTP(t *testing.T) {
	url, root := newUnsealedServer(t)
	rc, err := api.NewClient(api.Config{Address: url, Token: root})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	if err := rc.MountEnable("secret", "kv"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := rc.Write("secret/data/app/x", map[string]any{"a": "b"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Write a scoped policy and mint a token bound to it.
	if err := rc.PolicyWrite("app", `path "secret/data/app/*" { capabilities = ["read", "list"] }`); err != nil {
		t.Fatalf("policy write: %v", err)
	}
	names, err := rc.PolicyList()
	if err != nil {
		t.Fatalf("policy list: %v", err)
	}
	if !sliceContains(names, "app") || !sliceContains(names, "root") || !sliceContains(names, "default") {
		t.Fatalf("policy list = %v; want app, root, default", names)
	}
	auth, err := rc.TokenCreate(api.TokenCreateRequest{Policies: []string{"app"}})
	if err != nil || auth == nil {
		t.Fatalf("token create = %v, %v", auth, err)
	}
	if !sliceContains(auth.Policies, "app") || !sliceContains(auth.Policies, "default") {
		t.Fatalf("token policies = %v", auth.Policies)
	}

	sc, err := api.NewClient(api.Config{Address: url, Token: auth.ClientToken})
	if err != nil {
		t.Fatalf("scoped client: %v", err)
	}

	// Allowed read.
	if sec, err := sc.Read("secret/data/app/x"); err != nil || sec == nil || sec.Data["a"] != "b" {
		t.Fatalf("scoped read = %v, %v", sec, err)
	}
	// Denied write on the same path.
	if err := sc.Write("secret/data/app/x", map[string]any{"a": "c"}); err == nil {
		t.Fatal("scoped write should be denied")
	}
	// Denied elsewhere.
	if _, err := sc.Read("secret/other"); err == nil {
		t.Fatal("scoped read elsewhere should be denied")
	}
	// capabilities-self reflects the grant.
	caps, err := sc.CapabilitiesSelf("secret/data/app/x")
	if err != nil {
		t.Fatalf("capabilities-self: %v", err)
	}
	if !sliceContains(caps, "read") || !sliceContains(caps, "list") {
		t.Fatalf("capabilities = %v; want read, list", caps)
	}

	// Root still has full access.
	if _, err := rc.Read("secret/data/app/x"); err != nil {
		t.Fatalf("root read: %v", err)
	}
}
