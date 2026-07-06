package kv

import (
	"math/rand"
	"strconv"
	"testing"

	"github.com/jfigge/keephippo/internal/logical"
	"github.com/jfigge/keephippo/internal/physical"
)

type memV2 struct{ m map[string][]byte }

func newMemV2() *memV2 { return &memV2{m: map[string][]byte{}} }

func (s *memV2) Get(k string) (*logical.StorageEntry, error) {
	v, ok := s.m[k]
	if !ok {
		return nil, nil
	}
	return &logical.StorageEntry{Key: k, Value: v}, nil
}
func (s *memV2) Put(e *logical.StorageEntry) error { s.m[e.Key] = e.Value; return nil }
func (s *memV2) Delete(k string) error             { delete(s.m, k); return nil }
func (s *memV2) List(prefix string) ([]string, error) {
	keys := make([]string, 0, len(s.m))
	for k := range s.m {
		keys = append(keys, k)
	}
	return physical.Children(prefix, keys), nil
}

func v2req(op logical.Operation, path string, data map[string]any, st logical.Storage) *logical.Request {
	return &logical.Request{Operation: op, Path: path, Data: data, Storage: st}
}

func putV2(t *testing.T, b *V2Backend, st logical.Storage, key string, val string, cas *int) *logical.Response {
	t.Helper()
	body := map[string]any{"data": map[string]any{"val": val}}
	if cas != nil {
		body["options"] = map[string]any{"cas": *cas}
	}
	resp, err := b.HandleRequest(v2req(logical.UpdateOperation, "data/"+key, body, st))
	if err != nil {
		t.Fatalf("put %s: %v", key, err)
	}
	return resp
}

func TestKVv2Lifecycle(t *testing.T) {
	st := newMemV2()
	b := NewV2(st, nil)

	// Three writes → versions 1,2,3.
	putV2(t, b, st, "foo", "one", nil)
	putV2(t, b, st, "foo", "two", nil)
	resp := putV2(t, b, st, "foo", "three", nil)
	if v, _ := resp.Data["version"].(int); v != 3 {
		t.Fatalf("current version = %v, want 3", resp.Data["version"])
	}

	// Latest read returns version 3.
	got, err := b.HandleRequest(v2req(logical.ReadOperation, "data/foo", nil, st))
	if err != nil || got == nil {
		t.Fatalf("read latest: %v %v", got, err)
	}
	if data, _ := got.Data["data"].(map[string]any); data["val"] != "three" {
		t.Fatalf("latest val = %v", got.Data["data"])
	}

	// ?version=1 returns the first value.
	got, err = b.HandleRequest(&logical.Request{
		Operation: logical.ReadOperation, Path: "data/foo",
		Query: map[string][]string{"version": {"1"}}, Storage: st,
	})
	if err != nil || got == nil {
		t.Fatalf("read v1: %v %v", got, err)
	}
	if data, _ := got.Data["data"].(map[string]any); data["val"] != "one" {
		t.Fatalf("v1 val = %v", got.Data["data"])
	}

	// Soft-delete version 2, then read it → data nil but metadata present.
	if _, err := b.HandleRequest(v2req(logical.UpdateOperation, "delete/foo",
		map[string]any{"versions": []any{float64(2)}}, st)); err != nil {
		t.Fatalf("delete v2: %v", err)
	}
	got, _ = b.HandleRequest(&logical.Request{
		Operation: logical.ReadOperation, Path: "data/foo",
		Query: map[string][]string{"version": {"2"}}, Storage: st,
	})
	if got.Data["data"] != nil {
		t.Fatalf("deleted v2 data = %v, want nil", got.Data["data"])
	}

	// Undelete v2 restores it.
	if _, err := b.HandleRequest(v2req(logical.UpdateOperation, "undelete/foo",
		map[string]any{"versions": []any{float64(2)}}, st)); err != nil {
		t.Fatalf("undelete v2: %v", err)
	}
	got, _ = b.HandleRequest(&logical.Request{
		Operation: logical.ReadOperation, Path: "data/foo",
		Query: map[string][]string{"version": {"2"}}, Storage: st,
	})
	if data, _ := got.Data["data"].(map[string]any); data["val"] != "two" {
		t.Fatalf("undeleted v2 val = %v", got.Data["data"])
	}

	// Destroy v1: permanent, data gone even after read.
	if _, err := b.HandleRequest(v2req(logical.UpdateOperation, "destroy/foo",
		map[string]any{"versions": []any{float64(1)}}, st)); err != nil {
		t.Fatalf("destroy v1: %v", err)
	}
	if _, ok := st.m[versionKey("foo", 1)]; ok {
		t.Fatal("destroyed v1 data still in storage")
	}
	got, _ = b.HandleRequest(&logical.Request{
		Operation: logical.ReadOperation, Path: "data/foo",
		Query: map[string][]string{"version": {"1"}}, Storage: st,
	})
	if md, _ := got.Data["metadata"].(map[string]any); md["destroyed"] != true {
		t.Fatalf("v1 not marked destroyed: %v", got.Data["metadata"])
	}
}

func TestKVv2CAS(t *testing.T) {
	st := newMemV2()
	b := NewV2(st, map[string]any{"cas_required": true})

	// cas_required: a write without cas is rejected.
	_, err := b.HandleRequest(v2req(logical.UpdateOperation, "data/x",
		map[string]any{"data": map[string]any{"a": "b"}}, st))
	if ce, ok := err.(*logical.CodedError); !ok || ce.Status != 400 {
		t.Fatalf("no-cas write err = %v, want 400", err)
	}

	// cas=0 on a fresh key creates version 1.
	zero := 0
	putV2(t, b, st, "x", "v1", &zero)

	// Stale cas=0 now rejected (current is 1).
	_, err = b.HandleRequest(v2req(logical.UpdateOperation, "data/x",
		map[string]any{"data": map[string]any{"a": "c"}, "options": map[string]any{"cas": 0}}, st))
	if ce, ok := err.(*logical.CodedError); !ok || ce.Status != 400 {
		t.Fatalf("stale cas err = %v, want 400", err)
	}

	// Correct cas=1 succeeds.
	one := 1
	putV2(t, b, st, "x", "v2", &one)
}

// TestKVv2VersionMath drives random write/delete/destroy sequences under a
// max_versions cap and asserts the version-math invariants after every step.
func TestKVv2VersionMath(t *testing.T) {
	const maxVersions = 3
	rng := rand.New(rand.NewSource(1))

	for trial := 0; trial < 50; trial++ {
		st := newMemV2()
		b := NewV2(st, map[string]any{"max_versions": maxVersions})
		writes := 0

		for step := 0; step < 40; step++ {
			switch rng.Intn(3) {
			case 0, 1: // write (weighted)
				writes++
				putV2(t, b, st, "k", "val"+strconv.Itoa(writes), nil)
			case 2: // soft-delete a random live version
				md := mustMeta(t, b, "k")
				if md == nil {
					continue
				}
				vers := sortedVersionNums(md)
				if len(vers) == 0 {
					continue
				}
				pick := vers[rng.Intn(len(vers))]
				_, _ = b.HandleRequest(v2req(logical.UpdateOperation, "delete/k",
					map[string]any{"versions": []any{float64(pick)}}, st))
			}

			md := mustMeta(t, b, "k")
			if md == nil {
				continue
			}
			// Invariant 1: current_version == total writes.
			if md.CurrentVersion != writes {
				t.Fatalf("trial %d step %d: current=%d, writes=%d", trial, step, md.CurrentVersion, writes)
			}
			// Invariant 2: at most max_versions live slots retained.
			if len(md.Versions) > maxVersions {
				t.Fatalf("trial %d step %d: %d slots > max %d", trial, step, len(md.Versions), maxVersions)
			}
			// Invariant 3: oldest_version == max(1, current-max+1).
			wantOldest := md.CurrentVersion - maxVersions + 1
			if wantOldest < 1 {
				wantOldest = 1
			}
			if md.CurrentVersion > 0 && md.OldestVersion != wantOldest {
				t.Fatalf("trial %d step %d: oldest=%d, want %d", trial, step, md.OldestVersion, wantOldest)
			}
			// Invariant 4: evicted versions' data is gone from storage.
			for n := 1; n < md.OldestVersion; n++ {
				if _, ok := st.m[versionKey("k", n)]; ok {
					t.Fatalf("trial %d step %d: evicted v%d still stored", trial, step, n)
				}
			}
		}
	}
}

func mustMeta(t *testing.T, b *V2Backend, key string) *keyMetadata {
	t.Helper()
	md, err := b.loadMeta(key)
	if err != nil {
		t.Fatalf("loadMeta: %v", err)
	}
	return md
}
