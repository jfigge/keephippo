package approle

import (
	"testing"
	"time"

	"github.com/jfigge/keephippo/internal/logical"
	"github.com/jfigge/keephippo/internal/physical"
)

type memStorage struct{ m map[string][]byte }

func newMem() *memStorage { return &memStorage{m: map[string][]byte{}} }

func (s *memStorage) Get(k string) (*logical.StorageEntry, error) {
	v, ok := s.m[k]
	if !ok {
		return nil, nil
	}
	return &logical.StorageEntry{Key: k, Value: v}, nil
}
func (s *memStorage) Put(e *logical.StorageEntry) error { s.m[e.Key] = e.Value; return nil }
func (s *memStorage) Delete(k string) error             { delete(s.m, k); return nil }
func (s *memStorage) List(prefix string) ([]string, error) {
	keys := make([]string, 0, len(s.m))
	for k := range s.m {
		keys = append(keys, k)
	}
	return physical.Children(prefix, keys), nil
}

func req(op logical.Operation, path string, data map[string]any, st logical.Storage) *logical.Request {
	return &logical.Request{Operation: op, Path: path, Data: data, Storage: st}
}

// setup creates a role and returns (backend, storage, role_id).
func setup(t *testing.T, roleData map[string]any) (*Backend, *memStorage, string) {
	t.Helper()
	st := newMem()
	b := New(st)
	if _, err := b.HandleRequest(req(logical.UpdateOperation, "role/app", roleData, st)); err != nil {
		t.Fatalf("create role: %v", err)
	}
	resp, err := b.HandleRequest(req(logical.ReadOperation, "role/app/role-id", nil, st))
	if err != nil || resp == nil {
		t.Fatalf("read role-id: %v %v", resp, err)
	}
	rid, _ := resp.Data["role_id"].(string)
	if rid == "" {
		t.Fatal("empty role_id")
	}
	return b, st, rid
}

func genSecretID(t *testing.T, b *Backend, st *memStorage) string {
	t.Helper()
	resp, err := b.HandleRequest(req(logical.UpdateOperation, "role/app/secret-id", nil, st))
	if err != nil || resp == nil {
		t.Fatalf("gen secret-id: %v %v", resp, err)
	}
	sid, _ := resp.Data["secret_id"].(string)
	if sid == "" {
		t.Fatal("empty secret_id")
	}
	return sid
}

func login(b *Backend, st *memStorage, roleID, secretID string) (*logical.Response, error) {
	return b.HandleRequest(req(logical.UpdateOperation, "login",
		map[string]any{"role_id": roleID, "secret_id": secretID}, st))
}

func TestAppRoleLogin(t *testing.T) {
	b, st, rid := setup(t, map[string]any{"token_policies": "app,default", "token_ttl": "1h"})
	sid := genSecretID(t, b, st)

	resp, err := login(b, st, rid, sid)
	if err != nil || resp == nil || resp.Auth == nil {
		t.Fatalf("login: %v %v", resp, err)
	}
	if resp.Auth.ClientToken != "" {
		t.Fatal("backend must not mint a token")
	}
	if got := resp.Auth.Policies; len(got) != 2 || got[0] != "app" {
		t.Fatalf("policies = %v", got)
	}
	if resp.Auth.LeaseDuration != 3600 {
		t.Fatalf("lease = %d, want 3600", resp.Auth.LeaseDuration)
	}

	// Wrong secret_id is rejected.
	if _, err := login(b, st, rid, "not-a-real-secret-id"); err == nil {
		t.Fatal("wrong secret_id accepted")
	} else if ce, ok := err.(*logical.CodedError); !ok || ce.Status != 400 {
		t.Fatalf("wrong secret_id err = %v", err)
	}
}

func TestAppRoleSecretIDNumUses(t *testing.T) {
	b, st, rid := setup(t, map[string]any{"token_policies": "app", "secret_id_num_uses": 2})
	sid := genSecretID(t, b, st)

	for i := 0; i < 2; i++ {
		if _, err := login(b, st, rid, sid); err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
	}
	// Third use is spent → rejected.
	if _, err := login(b, st, rid, sid); err == nil {
		t.Fatal("spent secret_id still accepted")
	}
}

func TestAppRoleSecretIDTTL(t *testing.T) {
	b, st, rid := setup(t, map[string]any{"token_policies": "app", "secret_id_ttl": "10m"})
	base := time.Unix(1_700_000_000, 0)
	b.nowFn = func() time.Time { return base }
	sid := genSecretID(t, b, st)

	// Just before expiry: OK.
	b.nowFn = func() time.Time { return base.Add(9 * time.Minute) }
	if _, err := login(b, st, rid, sid); err != nil {
		t.Fatalf("login before expiry: %v", err)
	}

	// After expiry: rejected.
	b.nowFn = func() time.Time { return base.Add(11 * time.Minute) }
	if _, err := login(b, st, rid, sid); err == nil {
		t.Fatal("expired secret_id accepted")
	}
}

func TestAppRoleBindSecretIDFalse(t *testing.T) {
	b, st, rid := setup(t, map[string]any{"token_policies": "app", "bind_secret_id": false})
	// No secret_id required.
	resp, err := b.HandleRequest(req(logical.UpdateOperation, "login",
		map[string]any{"role_id": rid}, st))
	if err != nil || resp == nil || resp.Auth == nil {
		t.Fatalf("bind_secret_id=false login: %v %v", resp, err)
	}
}
