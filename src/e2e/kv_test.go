//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jfigge/keephippo/api"
	"github.com/jfigge/keephippo/internal/core"
	kphttp "github.com/jfigge/keephippo/internal/http"
	"github.com/jfigge/keephippo/internal/physical/inmem"
)

// newUnsealedServer starts a real, unsealed, in-memory server on a random port
// and returns its URL and root token.
func newUnsealedServer(t *testing.T) (string, string) {
	t.Helper()
	c := core.New(inmem.New(), "inmem")
	res, err := c.Initialize(core.InitParams{SecretShares: 1, SecretThreshold: 1})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, err := c.Unseal(res.Keys[0]); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	srv := httptest.NewServer(kphttp.NewServer(c).Handler())
	t.Cleanup(srv.Close)
	return srv.URL, res.RootToken
}

func TestKVLifecycleOverHTTP(t *testing.T) {
	url, root := newUnsealedServer(t)
	cl, err := api.NewClient(api.Config{Address: url, Token: root})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	if err := cl.MountEnable("secret", "kv"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := cl.Write("secret/foo", map[string]any{"a": "b"}); err != nil {
		t.Fatalf("write: %v", err)
	}
	sec, err := cl.Read("secret/foo")
	if err != nil || sec == nil || sec.Data["a"] != "b" {
		t.Fatalf("read = %v, %v", sec, err)
	}
	list, err := cl.List("secret/")
	if err != nil || list == nil {
		t.Fatalf("list = %v, %v", list, err)
	}
	if keys, _ := list.Data["keys"].([]any); len(keys) != 1 || keys[0] != "foo" {
		t.Fatalf("list keys = %v", list.Data["keys"])
	}
	if err := cl.Delete("secret/foo"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if sec, err := cl.Read("secret/foo"); err != nil || sec != nil {
		t.Fatalf("read after delete = %v, %v; want nil, nil", sec, err)
	}
}

// TestEnvelopeGolden asserts the read response is the exact Vault-compatible
// envelope: the right keys, in the right shape.
func TestEnvelopeGolden(t *testing.T) {
	url, root := newUnsealedServer(t)
	cl, err := api.NewClient(api.Config{Address: url, Token: root})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if err := cl.MountEnable("secret", "kv"); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := cl.Write("secret/env", map[string]any{"k": "v"}); err != nil {
		t.Fatalf("write: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, url+"/v1/secret/env", nil)
	req.Header.Set("X-Vault-Token", root)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	var env map[string]json.RawMessage
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("unmarshal: %v (%s)", err, body)
	}

	want := []string{"request_id", "lease_id", "renewable", "lease_duration", "data", "wrap_info", "warnings", "auth"}
	if len(env) != len(want) {
		t.Fatalf("envelope has %d keys, want %d; body=%s", len(env), len(want), body)
	}
	for _, k := range want {
		if _, ok := env[k]; !ok {
			t.Errorf("envelope missing key %q; body=%s", k, body)
		}
	}
	check := map[string]string{
		"lease_id":       `""`,
		"renewable":      `false`,
		"lease_duration": `0`,
		"wrap_info":      `null`,
		"warnings":       `null`,
		"auth":           `null`,
		"data":           `{"k":"v"}`,
	}
	for k, wantVal := range check {
		if got := string(env[k]); got != wantVal {
			t.Errorf("envelope[%q] = %s; want %s", k, got, wantVal)
		}
	}
	if got := string(env["request_id"]); len(got) < 3 || got == `""` {
		t.Errorf("request_id is empty: %s", got)
	}
}
