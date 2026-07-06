package http_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jfigge/keephippo/internal/core"
	kphttp "github.com/jfigge/keephippo/internal/http"
	"github.com/jfigge/keephippo/internal/physical/inmem"
)

func doTok(t *testing.T, h http.Handler, method, path, token string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec, out
}

func TestKVOverHTTP(t *testing.T) {
	c := core.New(inmem.New(), "inmem")
	res, err := c.Initialize(core.InitParams{SecretShares: 1, SecretThreshold: 1})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, err := c.Unseal(res.Keys[0]); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	root := res.RootToken
	h := kphttp.NewServer(c).Handler()

	// Enable kv at secret/.
	if rec, _ := doTok(t, h, "POST", "/v1/sys/mounts/secret", root, map[string]any{"type": "kv"}); rec.Code != http.StatusNoContent {
		t.Fatalf("enable mount = %d", rec.Code)
	}

	// Write a secret.
	if rec, _ := doTok(t, h, "PUT", "/v1/secret/foo", root, map[string]any{"a": "b"}); rec.Code != http.StatusNoContent {
		t.Fatalf("write = %d", rec.Code)
	}

	// Read it back — full envelope with data.a == "b".
	rec, body := doTok(t, h, "GET", "/v1/secret/foo", root, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("read = %d", rec.Code)
	}
	if _, ok := body["request_id"]; !ok {
		t.Fatalf("envelope missing request_id: %v", body)
	}
	if data, _ := body["data"].(map[string]any); data["a"] != "b" {
		t.Fatalf("read data = %v", body["data"])
	}

	// Auth failures.
	if rec, _ := doTok(t, h, "GET", "/v1/secret/foo", "", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("read no token = %d; want 400", rec.Code)
	}
	if rec, _ := doTok(t, h, "GET", "/v1/secret/foo", "bad-token", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("read bad token = %d; want 403", rec.Code)
	}

	// List via the LIST method.
	rec, body = doTok(t, h, "LIST", "/v1/secret/", root, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d", rec.Code)
	}
	data, _ := body["data"].(map[string]any)
	if keys, _ := data["keys"].([]any); len(keys) != 1 || keys[0] != "foo" {
		t.Fatalf("list keys = %v", data["keys"])
	}

	// Delete, then read → 404.
	if rec, _ := doTok(t, h, "DELETE", "/v1/secret/foo", root, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", rec.Code)
	}
	if rec, _ := doTok(t, h, "GET", "/v1/secret/foo", root, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("read after delete = %d; want 404", rec.Code)
	}

	// sys/mounts lists the engine.
	rec, body = doTok(t, h, "GET", "/v1/sys/mounts", root, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("mounts list = %d", rec.Code)
	}
	if data, _ := body["data"].(map[string]any); data["secret/"] == nil {
		t.Fatalf("mounts data = %v", body["data"])
	}
}
