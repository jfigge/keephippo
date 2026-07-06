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

func do(t *testing.T, h http.Handler, method, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec, out
}

func TestSysEndpointsLifecycle(t *testing.T) {
	h := kphttp.NewServer(core.New(inmem.New(), "inmem")).Handler()

	// Fresh: seal-status reports uninitialized + sealed.
	rec, body := do(t, h, "GET", "/v1/sys/seal-status", nil)
	if rec.Code != 200 || body["initialized"] != false || body["sealed"] != true {
		t.Fatalf("seal-status = %d %v", rec.Code, body)
	}

	// Health on an uninitialized server → 501.
	if rec, _ := do(t, h, "GET", "/v1/sys/health", nil); rec.Code != http.StatusNotImplemented {
		t.Fatalf("health(uninit) = %d; want 501", rec.Code)
	}

	// Initialize (single key).
	rec, body = do(t, h, "PUT", "/v1/sys/init", map[string]any{"secret_shares": 1, "secret_threshold": 1})
	if rec.Code != 200 {
		t.Fatalf("init = %d %v", rec.Code, body)
	}
	keys, _ := body["keys"].([]any)
	if len(keys) != 1 || body["root_token"] == nil || body["root_token"] == "" {
		t.Fatalf("init body = %v", body)
	}
	key0, _ := keys[0].(string)

	// Health while sealed → 503; catch-all under /v1 while sealed → 503.
	if rec, _ := do(t, h, "GET", "/v1/sys/health", nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("health(sealed) = %d; want 503", rec.Code)
	}
	if rec, _ := do(t, h, "GET", "/v1/secret/x", nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("catch-all(sealed) = %d; want 503", rec.Code)
	}

	// Unseal.
	rec, body = do(t, h, "PUT", "/v1/sys/unseal", map[string]any{"key": key0})
	if rec.Code != 200 || body["sealed"] != false {
		t.Fatalf("unseal = %d %v", rec.Code, body)
	}

	// Health OK; unmapped path now → 404.
	if rec, _ := do(t, h, "GET", "/v1/sys/health", nil); rec.Code != http.StatusOK {
		t.Fatalf("health(unsealed) = %d; want 200", rec.Code)
	}
	// Unsealed + no token → 400 (missing client token); auth precedes routing.
	if rec, _ := do(t, h, "GET", "/v1/secret/x", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("logical(unsealed, no token) = %d; want 400", rec.Code)
	}

	// Seal → 204; seal-status reflects it.
	if rec, _ := do(t, h, "PUT", "/v1/sys/seal", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("seal = %d; want 204", rec.Code)
	}
	if _, body := do(t, h, "GET", "/v1/sys/seal-status", nil); body["sealed"] != true {
		t.Fatalf("seal-status after seal = %v", body)
	}

	// Double init → 400.
	if rec, _ := do(t, h, "PUT", "/v1/sys/init", map[string]any{"secret_shares": 1, "secret_threshold": 1}); rec.Code != http.StatusBadRequest {
		t.Fatalf("double init = %d; want 400", rec.Code)
	}
}
