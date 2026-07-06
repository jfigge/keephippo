//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/jfigge/keephippo/api"
)

// TestIdentityAliasesToEntityGroupPolicy is the Phase 8 identity DoD: a userpass
// alias and an approle alias resolve to one entity; a policy granted to the
// entity's group applies to logins from either alias.
func TestIdentityAliasesToEntityGroupPolicy(t *testing.T) {
	url, root := newUnsealedServer(t)
	rc := mustClient(t, url, root)

	// Two auth methods + a shared secret guarded by the "shared" policy.
	if err := rc.AuthEnable("userpass", "userpass"); err != nil {
		t.Fatalf("enable userpass: %v", err)
	}
	if err := rc.AuthEnable("approle", "approle"); err != nil {
		t.Fatalf("enable approle: %v", err)
	}
	if err := rc.MountEnable("secret", "kv"); err != nil {
		t.Fatalf("mount: %v", err)
	}
	if err := rc.Write("secret/data/shared/x", map[string]any{"a": "b"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := rc.PolicyWrite("shared", `path "secret/data/shared/*" { capabilities = ["read"] }`); err != nil {
		t.Fatalf("policy: %v", err)
	}

	// Mount accessors (needed to key aliases).
	authList, err := rc.Do(http.MethodGet, "/v1/sys/auth", nil)
	if err != nil {
		t.Fatalf("sys/auth: %v", err)
	}
	upAcc := accessorOf(t, authList.Data, "userpass/")
	arAcc := accessorOf(t, authList.Data, "approle/")

	// Entity + group (group carries the "shared" policy).
	ent, err := rc.Do(http.MethodPost, "/v1/identity/entity", map[string]any{"name": "app-identity"})
	if err != nil {
		t.Fatalf("create entity: %v", err)
	}
	entityID, _ := ent.Data["id"].(string)
	if entityID == "" {
		t.Fatalf("no entity id: %v", ent.Data)
	}
	if _, err := rc.Do(http.MethodPost, "/v1/identity/group", map[string]any{
		"name": "app-group", "policies": "shared", "member_entity_ids": entityID,
	}); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// Users/roles with NO policies of their own — access comes only via identity.
	if err := rc.Write("auth/userpass/users/bob", map[string]any{"password": "pw"}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := rc.Write("auth/approle/role/app", map[string]any{}); err != nil {
		t.Fatalf("create role: %v", err)
	}

	// Aliases: userpass "bob" and approle "app" both point at the entity.
	for _, a := range []struct{ name, acc string }{{"bob", upAcc}, {"app", arAcc}} {
		if _, err := rc.Do(http.MethodPost, "/v1/identity/entity-alias", map[string]any{
			"name": a.name, "canonical_id": entityID, "mount_accessor": a.acc,
		}); err != nil {
			t.Fatalf("alias %s: %v", a.name, err)
		}
	}

	// Login via userpass → token carries the group policy + entity id.
	lc := mustClient(t, url, "")
	up, err := lc.Do(http.MethodPost, "/v1/auth/userpass/login/bob", map[string]any{"password": "pw"})
	if err != nil {
		t.Fatalf("userpass login: %v", err)
	}
	if !sliceContains(up.Auth.Policies, "shared") {
		t.Fatalf("userpass token missing 'shared' policy: %v", up.Auth.Policies)
	}
	assertCanRead(t, url, up.Auth.ClientToken)

	// Login via approle → same entity, same access.
	rid, _ := rc.Read("auth/approle/role/app/role-id")
	sid, err := rc.Do(http.MethodPost, "/v1/auth/approle/role/app/secret-id", map[string]any{})
	if err != nil {
		t.Fatalf("secret-id: %v", err)
	}
	ar, err := lc.Do(http.MethodPost, "/v1/auth/approle/login", map[string]any{
		"role_id": rid.Data["role_id"], "secret_id": sid.Data["secret_id"],
	})
	if err != nil {
		t.Fatalf("approle login: %v", err)
	}
	if !sliceContains(ar.Auth.Policies, "shared") {
		t.Fatalf("approle token missing 'shared' policy: %v", ar.Auth.Policies)
	}
	assertCanRead(t, url, ar.Auth.ClientToken)

	// Both tokens must report the same entity id.
	upLook, _ := rc.Do(http.MethodPost, "/v1/auth/token/lookup", map[string]any{"token": up.Auth.ClientToken})
	arLook, _ := rc.Do(http.MethodPost, "/v1/auth/token/lookup", map[string]any{"token": ar.Auth.ClientToken})
	if upLook.Data["entity_id"] != entityID || arLook.Data["entity_id"] != entityID {
		t.Fatalf("tokens not tied to one entity: %v vs %v", upLook.Data["entity_id"], arLook.Data["entity_id"])
	}
}

func accessorOf(t *testing.T, data map[string]any, path string) string {
	t.Helper()
	m, _ := data[path].(map[string]any)
	acc, _ := m["accessor"].(string)
	if acc == "" {
		t.Fatalf("no accessor for %s in %v", path, data)
	}
	return acc
}

func assertCanRead(t *testing.T, url, token string) {
	t.Helper()
	sc, err := api.NewClient(api.Config{Address: url, Token: token})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if sec, err := sc.Read("secret/data/shared/x"); err != nil || sec == nil || sec.Data["a"] != "b" {
		t.Fatalf("identity-scoped read failed: %v %v", sec, err)
	}
}
