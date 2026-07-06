//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAuditAndWrapCLI drives the Phase 7 CLI: enable a file audit device with an
// option, confirm secrets are obscured, then wrap a read with -wrap-ttl and
// unwrap it through the binary.
func TestAuditAndWrapCLI(t *testing.T) {
	addr, root := startCLIServer(t)
	env := []string{"KEEPHIPPO_ADDR=" + addr, "KEEPHIPPO_TOKEN=" + root}

	logPath := filepath.Join(t.TempDir(), "audit.log")
	mustRun(t, env, "", "audit", "enable", "file", "file_path="+logPath)
	if out := mustRun(t, env, "", "audit", "list"); !strings.Contains(out, "file") {
		t.Fatalf("audit list missing file device:\n%s", out)
	}

	mustRun(t, env, "", "secrets", "enable", "-path=secret", "kv")
	mustRun(t, env, "", "write", "secret/x", "password=TOPSECRET-CLI")

	blob, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	if strings.Contains(string(blob), "TOPSECRET-CLI") {
		t.Fatalf("plaintext secret leaked into audit log:\n%s", blob)
	}
	if !strings.Contains(string(blob), "hmac-sha256:") {
		t.Fatalf("no obscured fields in audit log:\n%s", blob)
	}

	// Wrap a read with the global -wrap-ttl flag; the CLI prints a wrapping token.
	wrapOut := mustRun(t, env, "", "-wrap-ttl=120s", "read", "secret/x")
	token := field(wrapOut, "wrapping_token:")
	if token == "" {
		t.Fatalf("no wrapping token in output:\n%s", wrapOut)
	}

	// Unwrap it once → the original data.
	if out := mustRun(t, env, "", "unwrap", token); !strings.Contains(out, "TOPSECRET-CLI") {
		t.Fatalf("unwrap did not return the secret:\n%s", out)
	}
	// Second unwrap fails.
	if _, code := runCLI(t, env, "", "unwrap", token); code == 0 {
		t.Fatal("second unwrap should fail")
	}
}
