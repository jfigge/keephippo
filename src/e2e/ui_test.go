//go:build e2e

package e2e

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jfigge/keephippo/internal/core"
	kphttp "github.com/jfigge/keephippo/internal/http"
	"github.com/jfigge/keephippo/internal/physical/inmem"
)

func newUIServer(t *testing.T, ui bool) string {
	t.Helper()
	c := core.New(inmem.New(), "inmem")
	res, err := c.Initialize(core.InitParams{SecretShares: 1, SecretThreshold: 1})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, err := c.Unseal(res.Keys[0]); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	srv := httptest.NewServer(kphttp.NewServer(c, kphttp.WithUI(ui)).Handler())
	t.Cleanup(srv.Close)
	t.Cleanup(func() { _ = c.Seal() })
	return srv.URL
}

// noRedirectClient returns a client that surfaces 3xx responses instead of
// following them.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func get(t *testing.T, hc *http.Client, url string) (*http.Response, string) {
	t.Helper()
	resp, err := hc.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body)
}

func TestUIServedWhenEnabled(t *testing.T) {
	url := newUIServer(t, true)
	hc := noRedirectClient()

	// The console page loads and references its assets + branding.
	resp, body := get(t, hc, url+"/ui/")
	if resp.StatusCode != 200 {
		t.Fatalf("/ui/ status = %d", resp.StatusCode)
	}
	for _, want := range []string{"keephippo", "app.js", "app.css", "/ui/icons/128x128.png"} {
		if !strings.Contains(body, want) {
			t.Fatalf("/ui/ page missing %q", want)
		}
	}

	// JS and CSS assets are served with sensible content types.
	resp, js := get(t, hc, url+"/ui/app.js")
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "javascript") {
		t.Fatalf("app.js status=%d ct=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(js, "runCommand") {
		t.Fatal("app.js missing the REPL implementation")
	}
	if resp, _ := get(t, hc, url+"/ui/app.css"); resp.StatusCode != 200 {
		t.Fatalf("app.css status = %d", resp.StatusCode)
	}

	// The embedded icon set is served as images.
	resp, _ = get(t, hc, url+"/ui/icons/32x32.png")
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("icon status=%d ct=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	// /favicon.ico is served as an image.
	resp, _ = get(t, hc, url+"/favicon.ico")
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "image/") {
		t.Fatalf("favicon status=%d ct=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	// "/" and "/ui" redirect to the console.
	for _, p := range []string{"/", "/ui"} {
		resp, _ = get(t, hc, url+p)
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/ui/" {
			t.Fatalf("%s: status=%d location=%q; want 302 -> /ui/", p, resp.StatusCode, resp.Header.Get("Location"))
		}
	}

	// The API still works alongside the UI.
	resp, _ = get(t, hc, url+"/v1/sys/seal-status")
	if resp.StatusCode != 200 {
		t.Fatalf("seal-status status = %d", resp.StatusCode)
	}
}

func TestSwaggerServedWhenEnabled(t *testing.T) {
	url := newUIServer(t, true)
	hc := noRedirectClient()

	// The Swagger UI host page loads and references the bundle + the spec.
	resp, body := get(t, hc, url+"/swagger/")
	if resp.StatusCode != 200 {
		t.Fatalf("/swagger/ status = %d", resp.StatusCode)
	}
	for _, want := range []string{"swagger-ui", "swagger-ui-bundle.js", "openapi.yaml"} {
		if !strings.Contains(body, want) {
			t.Fatalf("/swagger/ page missing %q", want)
		}
	}

	// The OpenAPI spec is embedded and served.
	resp, spec := get(t, hc, url+"/swagger/openapi.yaml")
	if resp.StatusCode != 200 {
		t.Fatalf("/swagger/openapi.yaml status = %d", resp.StatusCode)
	}
	for _, want := range []string{"openapi:", "/sys/health", "/auth/userpass/login/{username}"} {
		if !strings.Contains(spec, want) {
			t.Fatalf("openapi.yaml missing %q", want)
		}
	}

	// The Swagger UI JavaScript bundle is served as JavaScript.
	resp, _ = get(t, hc, url+"/swagger/swagger-ui-bundle.js")
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "javascript") {
		t.Fatalf("swagger-ui-bundle.js status=%d ct=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}

	// "/swagger" redirects to the trailing-slash form.
	resp, _ = get(t, hc, url+"/swagger")
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/swagger/" {
		t.Fatalf("/swagger: status=%d location=%q; want 302 -> /swagger/", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestUINotServedWhenDisabled(t *testing.T) {
	url := newUIServer(t, false)
	hc := noRedirectClient()

	if resp, _ := get(t, hc, url+"/ui/"); resp.StatusCode != 404 {
		t.Fatalf("/ui/ with ui=false status = %d; want 404", resp.StatusCode)
	}
	if resp, _ := get(t, hc, url+"/swagger/"); resp.StatusCode != 404 {
		t.Fatalf("/swagger/ with ui=false status = %d; want 404", resp.StatusCode)
	}
	if resp, _ := get(t, hc, url+"/favicon.ico"); resp.StatusCode != 404 {
		t.Fatalf("/favicon.ico with ui=false status = %d; want 404", resp.StatusCode)
	}
	// "/" must not redirect to the UI when it is disabled.
	if resp, _ := get(t, hc, url+"/"); resp.StatusCode == http.StatusFound {
		t.Fatal("/ redirected to the UI even though ui=false")
	}
}
