package kv_test

import (
	"reflect"
	"testing"

	"github.com/jfigge/keephippo/builtin/logical/kv"
	"github.com/jfigge/keephippo/internal/logical"
	"github.com/jfigge/keephippo/internal/physical"
)

// memStorage is an in-memory logical.Storage for tests.
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

func TestKVCRUD(t *testing.T) {
	st := newMem()
	b := kv.New(st)

	// Write then read.
	if _, err := b.HandleRequest(req(logical.CreateOperation, "foo", map[string]any{"a": "b"}, st)); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := b.HandleRequest(req(logical.ReadOperation, "foo", nil, st))
	if err != nil || resp == nil || resp.Data["a"] != "b" {
		t.Fatalf("read = %v, %v", resp, err)
	}

	// Missing read → nil, nil (404 at the HTTP layer).
	if resp, err := b.HandleRequest(req(logical.ReadOperation, "nope", nil, st)); err != nil || resp != nil {
		t.Fatalf("read missing = %v, %v; want nil, nil", resp, err)
	}

	// List returns children with Vault semantics.
	if _, err := b.HandleRequest(req(logical.CreateOperation, "bar/baz", map[string]any{"x": "y"}, st)); err != nil {
		t.Fatalf("write bar/baz: %v", err)
	}
	resp, _ = b.HandleRequest(req(logical.ListOperation, "", nil, st))
	if keys, _ := resp.Data["keys"].([]string); !reflect.DeepEqual(keys, []string{"bar/", "foo"}) {
		t.Fatalf("list keys = %v; want [bar/ foo]", resp.Data["keys"])
	}

	// Delete.
	if _, err := b.HandleRequest(req(logical.DeleteOperation, "foo", nil, st)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if resp, _ := b.HandleRequest(req(logical.ReadOperation, "foo", nil, st)); resp != nil {
		t.Fatal("entry still present after delete")
	}
}
