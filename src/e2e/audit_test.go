//go:build e2e

package e2e

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFileAuditObscuresSecrets enables a file audit device, performs a write
// carrying a secret, and asserts the log records the request path but never the
// plaintext secret (it is HMAC-obscured).
func TestFileAuditObscuresSecrets(t *testing.T) {
	url, root := newUnsealedServer(t)
	rc := mustClient(t, url, root)

	logPath := filepath.Join(t.TempDir(), "audit.log")
	if _, err := rc.Do(http.MethodPost, "/v1/sys/audit/file",
		map[string]any{"type": "file", "file_path": logPath}); err != nil {
		t.Fatalf("enable file audit: %v", err)
	}

	if err := rc.MountEnable("secret", "kv"); err != nil {
		t.Fatalf("mount: %v", err)
	}
	const secret = "SUPERSECRET-PLAINTEXT-9000"
	if err := rc.Write("secret/apitest", map[string]any{"password": secret}); err != nil {
		t.Fatalf("write: %v", err)
	}

	blob, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	log := string(blob)
	if !strings.Contains(log, "secret/apitest") {
		t.Fatalf("audit log is missing the request path:\n%s", log)
	}
	if strings.Contains(log, secret) {
		t.Fatalf("PLAINTEXT SECRET LEAKED into the audit log:\n%s", log)
	}
	if !strings.Contains(log, "hmac-sha256:") {
		t.Fatalf("audit log has no HMAC-obscured fields:\n%s", log)
	}
	// The root token must also be obscured (never appears verbatim).
	if strings.Contains(log, root) {
		t.Fatal("root token appeared in cleartext in the audit log")
	}
}

// TestAuditListAndDisable exercises the sys/audit lifecycle over HTTP.
func TestAuditListAndDisable(t *testing.T) {
	url, root := newUnsealedServer(t)
	rc := mustClient(t, url, root)

	logPath := filepath.Join(t.TempDir(), "a.log")
	if _, err := rc.Do(http.MethodPost, "/v1/sys/audit/file",
		map[string]any{"type": "file", "file_path": logPath}); err != nil {
		t.Fatalf("enable: %v", err)
	}
	list, err := rc.Do(http.MethodGet, "/v1/sys/audit", nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if _, ok := list.Data["file/"]; !ok {
		t.Fatalf("file/ device not listed: %v", list.Data)
	}
	if _, err := rc.Do(http.MethodDelete, "/v1/sys/audit/file", nil); err != nil {
		t.Fatalf("disable: %v", err)
	}
	list, _ = rc.Do(http.MethodGet, "/v1/sys/audit", nil)
	if _, ok := list.Data["file/"]; ok {
		t.Fatal("file/ device still listed after disable")
	}
}
