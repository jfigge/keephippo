package cubbyhole_test

import (
	"testing"

	"github.com/jfigge/keephippo/builtin/logical/cubbyhole"
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

func do(t *testing.T, b *cubbyhole.Backend, op logical.Operation, token, path string, data map[string]any, st logical.Storage) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(&logical.Request{Operation: op, Path: path, Data: data, ClientToken: token, Storage: st})
	if err != nil {
		t.Fatalf("%s %s (token %s): %v", op, path, token, err)
	}
	return resp
}

func TestCubbyholePerTokenIsolation(t *testing.T) {
	st := newMem()
	b := cubbyhole.New(st)

	// Two tokens write the same path with different values.
	do(t, b, logical.UpdateOperation, "tokenA", "secret", map[string]any{"who": "alice"}, st)
	do(t, b, logical.UpdateOperation, "tokenB", "secret", map[string]any{"who": "bob"}, st)

	if r := do(t, b, logical.ReadOperation, "tokenA", "secret", nil, st); r.Data["who"] != "alice" {
		t.Fatalf("tokenA sees %v", r.Data)
	}
	if r := do(t, b, logical.ReadOperation, "tokenB", "secret", nil, st); r.Data["who"] != "bob" {
		t.Fatalf("tokenB sees %v", r.Data)
	}

	// A missing token has nothing.
	if r := do(t, b, logical.ReadOperation, "tokenC", "secret", nil, st); r != nil {
		t.Fatalf("tokenC unexpectedly sees %v", r.Data)
	}

	// Purging tokenA leaves tokenB intact.
	if err := cubbyhole.Purge(st, "tokenA"); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if r := do(t, b, logical.ReadOperation, "tokenA", "secret", nil, st); r != nil {
		t.Fatal("tokenA data survived purge")
	}
	if r := do(t, b, logical.ReadOperation, "tokenB", "secret", nil, st); r.Data["who"] != "bob" {
		t.Fatal("tokenB data lost after purging tokenA")
	}
}

func TestCubbyholeRequiresToken(t *testing.T) {
	st := newMem()
	b := cubbyhole.New(st)
	if _, err := b.HandleRequest(&logical.Request{Operation: logical.ReadOperation, Path: "x", Storage: st}); err == nil {
		t.Fatal("cubbyhole without a token should error")
	}
}
