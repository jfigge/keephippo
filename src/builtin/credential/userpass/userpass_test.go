package userpass_test

import (
	"testing"

	"github.com/jfigge/keephippo/builtin/credential/userpass"
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

func TestUserpassLifecycle(t *testing.T) {
	st := newMem()
	b := userpass.New(st)

	// Create a user with a password and policies.
	if _, err := b.HandleRequest(req(logical.UpdateOperation, "users/alice",
		map[string]any{"password": "s3cret", "token_policies": "app,default", "token_ttl": "30m"}, st)); err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Read must not expose the password hash.
	resp, err := b.HandleRequest(req(logical.ReadOperation, "users/alice", nil, st))
	if err != nil || resp == nil {
		t.Fatalf("read user: %v %v", resp, err)
	}
	if _, leaked := resp.Data["password_hash"]; leaked {
		t.Fatal("read leaked password_hash")
	}
	if pols, _ := resp.Data["token_policies"].([]string); len(pols) != 2 {
		t.Fatalf("policies = %v", resp.Data["token_policies"])
	}

	// Login with the correct password mints an Auth with the user's policies.
	resp, err = b.HandleRequest(req(logical.UpdateOperation, "login/alice",
		map[string]any{"password": "s3cret"}, st))
	if err != nil || resp == nil || resp.Auth == nil {
		t.Fatalf("login: %v %v", resp, err)
	}
	if resp.Auth.ClientToken != "" {
		t.Fatal("backend must not mint a token; core does that")
	}
	if got := resp.Auth.Policies; len(got) != 2 || got[0] != "app" {
		t.Fatalf("auth policies = %v", got)
	}
	if resp.Auth.LeaseDuration != 1800 {
		t.Fatalf("lease = %d, want 1800", resp.Auth.LeaseDuration)
	}

	// Wrong password is rejected with 400.
	_, err = b.HandleRequest(req(logical.UpdateOperation, "login/alice",
		map[string]any{"password": "nope"}, st))
	if ce, ok := err.(*logical.CodedError); !ok || ce.Status != 400 {
		t.Fatalf("wrong password err = %v, want 400 CodedError", err)
	}

	// Unknown user is rejected the same way (no user-enumeration signal).
	_, err = b.HandleRequest(req(logical.UpdateOperation, "login/ghost",
		map[string]any{"password": "whatever"}, st))
	if ce, ok := err.(*logical.CodedError); !ok || ce.Status != 400 {
		t.Fatalf("unknown user err = %v, want 400 CodedError", err)
	}
}

func TestUserpassUpdateKeepsPassword(t *testing.T) {
	st := newMem()
	b := userpass.New(st)
	if _, err := b.HandleRequest(req(logical.UpdateOperation, "users/bob",
		map[string]any{"password": "pw", "token_policies": "a"}, st)); err != nil {
		t.Fatal(err)
	}
	// Update policies only, no password.
	if _, err := b.HandleRequest(req(logical.UpdateOperation, "users/bob",
		map[string]any{"token_policies": "a,b"}, st)); err != nil {
		t.Fatal(err)
	}
	// Original password still works.
	if _, err := b.HandleRequest(req(logical.UpdateOperation, "login/bob",
		map[string]any{"password": "pw"}, st)); err != nil {
		t.Fatalf("login after policy-only update: %v", err)
	}
}
