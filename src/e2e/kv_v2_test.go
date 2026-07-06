//go:build e2e

package e2e

import (
	"net/http"
	"testing"
)

// TestKVv2LifecycleOverHTTP drives the Phase 5 KV v2 DoD end-to-end: versioning,
// ?version reads, soft-delete/undelete, destroy, CAS, and CLI version detection
// via sys/internal/ui/mounts.
func TestKVv2LifecycleOverHTTP(t *testing.T) {
	url, root := newUnsealedServer(t)
	rc := mustClient(t, url, root)

	// Enable a v2 mount.
	if _, err := rc.Do(http.MethodPost, "/v1/sys/mounts/kv2",
		map[string]any{"type": "kv", "options": map[string]any{"version": "2"}}); err != nil {
		t.Fatalf("enable v2: %v", err)
	}

	// Version detection endpoint reports v2.
	ui, err := rc.Do(http.MethodGet, "/v1/sys/internal/ui/mounts/kv2/foo", nil)
	if err != nil {
		t.Fatalf("ui/mounts: %v", err)
	}
	if opts, _ := ui.Data["options"].(map[string]any); opts["version"] != "2" {
		t.Fatalf("detected version = %v; want 2", ui.Data["options"])
	}

	// Three writes → versions 1,2,3.
	for i, val := range []string{"one", "two", "three"} {
		resp, err := rc.Do(http.MethodPut, "/v1/kv2/data/foo",
			map[string]any{"data": map[string]any{"val": val}})
		if err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		if v, _ := resp.Data["version"].(float64); int(v) != i+1 {
			t.Fatalf("write %d version = %v", i, resp.Data["version"])
		}
	}

	// Latest read returns version 3.
	got, err := rc.Do(http.MethodGet, "/v1/kv2/data/foo", nil)
	if err != nil {
		t.Fatalf("read latest: %v", err)
	}
	if data, _ := got.Data["data"].(map[string]any); data["val"] != "three" {
		t.Fatalf("latest = %v", got.Data["data"])
	}

	// ?version=1 returns the first value.
	got, err = rc.Do(http.MethodGet, "/v1/kv2/data/foo?version=1", nil)
	if err != nil {
		t.Fatalf("read v1: %v", err)
	}
	if data, _ := got.Data["data"].(map[string]any); data["val"] != "one" {
		t.Fatalf("v1 = %v", got.Data["data"])
	}

	// metadata shows current_version 3.
	md, err := rc.Do(http.MethodGet, "/v1/kv2/metadata/foo", nil)
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	if cv, _ := md.Data["current_version"].(float64); int(cv) != 3 {
		t.Fatalf("current_version = %v", md.Data["current_version"])
	}

	// Soft-delete v2 → data nil, metadata present.
	if _, err := rc.Do(http.MethodPut, "/v1/kv2/delete/foo",
		map[string]any{"versions": []int{2}}); err != nil {
		t.Fatalf("delete v2: %v", err)
	}
	got, _ = rc.Do(http.MethodGet, "/v1/kv2/data/foo?version=2", nil)
	if got.Data["data"] != nil {
		t.Fatalf("deleted v2 data = %v; want nil", got.Data["data"])
	}

	// Undelete v2 restores it.
	if _, err := rc.Do(http.MethodPut, "/v1/kv2/undelete/foo",
		map[string]any{"versions": []int{2}}); err != nil {
		t.Fatalf("undelete v2: %v", err)
	}
	got, _ = rc.Do(http.MethodGet, "/v1/kv2/data/foo?version=2", nil)
	if data, _ := got.Data["data"].(map[string]any); data["val"] != "two" {
		t.Fatalf("undeleted v2 = %v", got.Data["data"])
	}

	// Destroy v1 → permanent.
	if _, err := rc.Do(http.MethodPut, "/v1/kv2/destroy/foo",
		map[string]any{"versions": []int{1}}); err != nil {
		t.Fatalf("destroy v1: %v", err)
	}
	got, _ = rc.Do(http.MethodGet, "/v1/kv2/data/foo?version=1", nil)
	if md, _ := got.Data["metadata"].(map[string]any); md["destroyed"] != true {
		t.Fatalf("v1 not destroyed: %v", got.Data["metadata"])
	}
}

func TestKVv2CASOverHTTP(t *testing.T) {
	url, root := newUnsealedServer(t)
	rc := mustClient(t, url, root)

	if _, err := rc.Do(http.MethodPost, "/v1/sys/mounts/kv3",
		map[string]any{"type": "kv", "options": map[string]any{"version": "2", "cas_required": "true"}}); err != nil {
		t.Fatalf("enable v2 cas: %v", err)
	}

	// cas_required: a write without cas fails.
	if _, err := rc.Do(http.MethodPut, "/v1/kv3/data/x",
		map[string]any{"data": map[string]any{"a": "b"}}); err == nil {
		t.Fatal("write without cas should fail")
	}

	// cas=0 creates version 1.
	if _, err := rc.Do(http.MethodPut, "/v1/kv3/data/x",
		map[string]any{"data": map[string]any{"a": "b"}, "options": map[string]any{"cas": 0}}); err != nil {
		t.Fatalf("cas=0 write: %v", err)
	}

	// Stale cas=0 now rejected.
	if _, err := rc.Do(http.MethodPut, "/v1/kv3/data/x",
		map[string]any{"data": map[string]any{"a": "c"}, "options": map[string]any{"cas": 0}}); err == nil {
		t.Fatal("stale cas=0 should fail")
	}
}
