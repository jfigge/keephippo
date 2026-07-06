package core_test

import (
	"errors"
	"testing"

	"github.com/jfigge/keephippo/internal/core"
	"github.com/jfigge/keephippo/internal/logical"
	"github.com/jfigge/keephippo/internal/physical/inmem"
)

func setupUnsealed(t *testing.T) (*core.Core, string) {
	t.Helper()
	c := core.New(inmem.New(), "inmem")
	res, err := c.Initialize(core.InitParams{SecretShares: 1, SecretThreshold: 1})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, err := c.Unseal(res.Keys[0]); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	return c, res.RootToken
}

func assertCoded(t *testing.T, err error, want int) {
	t.Helper()
	var ce *core.CodedError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v; want *CodedError", err)
	}
	if ce.Status != want {
		t.Fatalf("status = %d; want %d", ce.Status, want)
	}
}

func TestMountAndKVFlow(t *testing.T) {
	c, root := setupUnsealed(t)
	if err := c.EnableMount("secret", "kv", nil); err != nil {
		t.Fatalf("enable: %v", err)
	}

	write := &logical.Request{Operation: logical.CreateOperation, Path: "secret/foo", Data: map[string]any{"a": "b"}, ClientToken: root}
	if _, err := c.HandleRequest(write); err != nil {
		t.Fatalf("write: %v", err)
	}

	resp, err := c.HandleRequest(&logical.Request{Operation: logical.ReadOperation, Path: "secret/foo", ClientToken: root})
	if err != nil || resp == nil || resp.Data["a"] != "b" {
		t.Fatalf("read = %v, %v", resp, err)
	}

	resp, err = c.HandleRequest(&logical.Request{Operation: logical.ListOperation, Path: "secret/", ClientToken: root})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if keys, _ := resp.Data["keys"].([]string); len(keys) != 1 || keys[0] != "foo" {
		t.Fatalf("list keys = %v; want [foo]", resp.Data["keys"])
	}

	if _, err := c.HandleRequest(&logical.Request{Operation: logical.DeleteOperation, Path: "secret/foo", ClientToken: root}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if resp, _ := c.HandleRequest(&logical.Request{Operation: logical.ReadOperation, Path: "secret/foo", ClientToken: root}); resp != nil {
		t.Fatal("entry still present after delete")
	}
}

func TestAuthAndRouting(t *testing.T) {
	c, root := setupUnsealed(t)
	if err := c.EnableMount("secret", "kv", nil); err != nil {
		t.Fatalf("enable: %v", err)
	}

	_, err := c.HandleRequest(&logical.Request{Operation: logical.ReadOperation, Path: "secret/x"})
	assertCoded(t, err, 400) // missing token

	_, err = c.HandleRequest(&logical.Request{Operation: logical.ReadOperation, Path: "secret/x", ClientToken: "nope"})
	assertCoded(t, err, 403) // invalid token

	_, err = c.HandleRequest(&logical.Request{Operation: logical.ReadOperation, Path: "nomount/x", ClientToken: root})
	assertCoded(t, err, 404) // authenticated but unmapped
}

func TestMountPersistsAcrossRestart(t *testing.T) {
	phys := inmem.New()
	c1 := core.New(phys, "inmem")
	res, err := c1.Initialize(core.InitParams{SecretShares: 1, SecretThreshold: 1})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, err := c1.Unseal(res.Keys[0]); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if err := c1.EnableMount("secret", "kv", nil); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if _, err := c1.HandleRequest(&logical.Request{Operation: logical.CreateOperation, Path: "secret/foo", Data: map[string]any{"a": "b"}, ClientToken: res.RootToken}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Restart: new core over the same storage, unseal, mount must be back.
	c2 := core.New(phys, "inmem")
	if _, err := c2.Unseal(res.Keys[0]); err != nil {
		t.Fatalf("re-unseal: %v", err)
	}
	if ms := c2.ListMounts(); len(ms) != 1 || ms[0].Path != "secret/" {
		t.Fatalf("mounts after restart = %+v", ms)
	}
	resp, err := c2.HandleRequest(&logical.Request{Operation: logical.ReadOperation, Path: "secret/foo", ClientToken: res.RootToken})
	if err != nil || resp == nil || resp.Data["a"] != "b" {
		t.Fatalf("read after restart = %v, %v", resp, err)
	}
}

func TestRemountPreservesData(t *testing.T) {
	c, root := setupUnsealed(t)
	if err := c.EnableMount("secret", "kv", nil); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if _, err := c.HandleRequest(&logical.Request{Operation: logical.CreateOperation, Path: "secret/foo", Data: map[string]any{"a": "b"}, ClientToken: root}); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := c.Remount("secret", "kv"); err != nil {
		t.Fatalf("remount: %v", err)
	}

	// Old path no longer routes.
	_, err := c.HandleRequest(&logical.Request{Operation: logical.ReadOperation, Path: "secret/foo", ClientToken: root})
	assertCoded(t, err, 404)

	// New path serves the preserved data.
	resp, err := c.HandleRequest(&logical.Request{Operation: logical.ReadOperation, Path: "kv/foo", ClientToken: root})
	if err != nil || resp == nil || resp.Data["a"] != "b" {
		t.Fatalf("read at new path = %v, %v", resp, err)
	}
}

func TestAuthorizeScopedPolicy(t *testing.T) {
	c, root := setupUnsealed(t)
	if err := c.EnableMount("secret", "kv", nil); err != nil {
		t.Fatalf("enable: %v", err)
	}
	rootReq := func(op logical.Operation, path string, data map[string]any) (*logical.Response, error) {
		return c.HandleRequest(&logical.Request{Operation: op, Path: path, Data: data, ClientToken: root})
	}

	if _, err := rootReq(logical.CreateOperation, "secret/data/app/x", map[string]any{"a": "b"}); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	// Write a scoped policy: read+list on secret/data/app/*.
	if _, err := rootReq(logical.UpdateOperation, "sys/policies/acl/app", map[string]any{
		"policy": `path "secret/data/app/*" { capabilities = ["read", "list"] }`,
	}); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	// Mint a token bound to it.
	created, err := rootReq(logical.UpdateOperation, "auth/token/create", map[string]any{"policies": []any{"app"}})
	if err != nil || created.Auth == nil {
		t.Fatalf("token create = %v, %v", created, err)
	}
	scoped := created.Auth.ClientToken

	scopedReq := func(op logical.Operation, path string, data map[string]any) (*logical.Response, error) {
		return c.HandleRequest(&logical.Request{Operation: op, Path: path, Data: data, ClientToken: scoped})
	}

	// Can read the allowed path.
	if r, err := scopedReq(logical.ReadOperation, "secret/data/app/x", nil); err != nil || r == nil || r.Data["a"] != "b" {
		t.Fatalf("scoped read = %v, %v", r, err)
	}
	// Cannot write there.
	_, err = scopedReq(logical.UpdateOperation, "secret/data/app/x", map[string]any{"a": "c"})
	assertCoded(t, err, 403)
	// Denied everywhere else.
	_, err = scopedReq(logical.ReadOperation, "secret/other", nil)
	assertCoded(t, err, 403)
	// But self endpoints always work.
	if _, err := scopedReq(logical.ReadOperation, "auth/token/lookup-self", nil); err != nil {
		t.Fatalf("lookup-self denied: %v", err)
	}
	// Root still has full access.
	if r, err := rootReq(logical.ReadOperation, "secret/data/app/x", nil); err != nil || r == nil {
		t.Fatalf("root read = %v, %v", r, err)
	}
}
