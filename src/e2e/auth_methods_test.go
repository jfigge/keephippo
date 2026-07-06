//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/jfigge/keephippo/api"
)

// TestUserpassLoginOverHTTP drives the Phase 5 userpass DoD: enable the method,
// create a user bound to a scoped policy, log in, and confirm the minted token
// obeys that policy.
func TestUserpassLoginOverHTTP(t *testing.T) {
	url, root := newUnsealedServer(t)
	rc := mustClient(t, url, root)

	if err := rc.MountEnable("secret", "kv"); err != nil {
		t.Fatalf("mount: %v", err)
	}
	if err := rc.Write("secret/data/app/x", map[string]any{"a": "b"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := rc.AuthEnable("userpass", "userpass"); err != nil {
		t.Fatalf("auth enable: %v", err)
	}
	if err := rc.PolicyWrite("app", `path "secret/data/app/*" { capabilities = ["read", "list"] }`); err != nil {
		t.Fatalf("policy: %v", err)
	}
	if err := rc.Write("auth/userpass/users/alice",
		map[string]any{"password": "s3cret", "token_policies": "app"}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Log in with no token.
	lc := mustClient(t, url, "")
	resp, err := lc.Do(http.MethodPost, "/v1/auth/userpass/login/alice",
		map[string]any{"password": "s3cret"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if resp.Auth == nil || resp.Auth.ClientToken == "" {
		t.Fatalf("login returned no token: %+v", resp)
	}
	if !sliceContains(resp.Auth.Policies, "app") || !sliceContains(resp.Auth.Policies, "default") {
		t.Fatalf("token policies = %v; want app + default", resp.Auth.Policies)
	}

	// Wrong password is rejected.
	if _, err := lc.Do(http.MethodPost, "/v1/auth/userpass/login/alice",
		map[string]any{"password": "wrong"}); err == nil {
		t.Fatal("wrong password accepted")
	}

	// The minted token can read the allowed path but nothing else.
	sc := mustClient(t, url, resp.Auth.ClientToken)
	if sec, err := sc.Read("secret/data/app/x"); err != nil || sec == nil || sec.Data["a"] != "b" {
		t.Fatalf("scoped read = %v, %v", sec, err)
	}
	if _, err := sc.Read("secret/data/other"); err == nil {
		t.Fatal("scoped read elsewhere should be denied")
	}
}

// TestAppRoleLoginOverHTTP drives the Phase 5 AppRole DoD: role_id + secret_id
// exchange for a token scoped to the role's policies.
func TestAppRoleLoginOverHTTP(t *testing.T) {
	url, root := newUnsealedServer(t)
	rc := mustClient(t, url, root)

	if err := rc.MountEnable("secret", "kv"); err != nil {
		t.Fatalf("mount: %v", err)
	}
	if err := rc.Write("secret/data/machine/y", map[string]any{"m": "n"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := rc.AuthEnable("approle", "approle"); err != nil {
		t.Fatalf("auth enable: %v", err)
	}
	if err := rc.PolicyWrite("machine", `path "secret/data/machine/*" { capabilities = ["read"] }`); err != nil {
		t.Fatalf("policy: %v", err)
	}
	if err := rc.Write("auth/approle/role/app",
		map[string]any{"token_policies": "machine", "secret_id_num_uses": 5}); err != nil {
		t.Fatalf("create role: %v", err)
	}

	// Fetch the role_id and generate a secret_id.
	ridResp, err := rc.Read("auth/approle/role/app/role-id")
	if err != nil || ridResp == nil {
		t.Fatalf("role-id: %v %v", ridResp, err)
	}
	roleID, _ := ridResp.Data["role_id"].(string)
	sidResp, err := rc.Do(http.MethodPost, "/v1/auth/approle/role/app/secret-id", map[string]any{})
	if err != nil {
		t.Fatalf("secret-id: %v", err)
	}
	secretID, _ := sidResp.Data["secret_id"].(string)
	if roleID == "" || secretID == "" {
		t.Fatalf("empty role_id/secret_id: %q %q", roleID, secretID)
	}

	// Log in with no token.
	lc := mustClient(t, url, "")
	resp, err := lc.Do(http.MethodPost, "/v1/auth/approle/login",
		map[string]any{"role_id": roleID, "secret_id": secretID})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if resp.Auth == nil || resp.Auth.ClientToken == "" {
		t.Fatalf("login returned no token: %+v", resp)
	}
	if !sliceContains(resp.Auth.Policies, "machine") {
		t.Fatalf("token policies = %v; want machine", resp.Auth.Policies)
	}

	// Bad secret_id is rejected.
	if _, err := lc.Do(http.MethodPost, "/v1/auth/approle/login",
		map[string]any{"role_id": roleID, "secret_id": "bogus"}); err == nil {
		t.Fatal("bad secret_id accepted")
	}

	// The token obeys the role's ACL.
	sc := mustClient(t, url, resp.Auth.ClientToken)
	if sec, err := sc.Read("secret/data/machine/y"); err != nil || sec == nil || sec.Data["m"] != "n" {
		t.Fatalf("scoped read = %v, %v", sec, err)
	}
	if _, err := sc.Read("secret/data/machine/y"); err != nil {
		// second read must still work (token not single-use)
		t.Fatalf("second scoped read: %v", err)
	}
}

func mustClient(t *testing.T, url, token string) *api.Client {
	t.Helper()
	c, err := api.NewClient(api.Config{Address: url, Token: token})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return c
}
