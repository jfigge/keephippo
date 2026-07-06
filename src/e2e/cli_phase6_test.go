//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// TestTransitCLI drives the transit CLI: key create, encrypt→decrypt round-trip
// (the CLI base64-encodes for you), rotation, and rewrap.
func TestTransitCLI(t *testing.T) {
	addr, root := startCLIServer(t)
	env := []string{"KEEPHIPPO_ADDR=" + addr, "KEEPHIPPO_TOKEN=" + root}

	mustRun(t, env, "", "secrets", "enable", "transit")
	mustRun(t, env, "", "transit", "key", "create", "app")

	ct := strings.TrimSpace(mustRun(t, env, "", "transit", "encrypt", "app", "hello world"))
	if !strings.HasPrefix(ct, "vault:v1:") {
		t.Fatalf("ciphertext = %q", ct)
	}
	if out := strings.TrimSpace(mustRun(t, env, "", "transit", "decrypt", "app", ct)); out != "hello world" {
		t.Fatalf("decrypt = %q; want 'hello world'", out)
	}

	mustRun(t, env, "", "transit", "key", "rotate", "app")
	ct2 := strings.TrimSpace(mustRun(t, env, "", "transit", "rewrap", "app", ct))
	if !strings.HasPrefix(ct2, "vault:v2:") {
		t.Fatalf("rewrapped = %q", ct2)
	}
	if out := strings.TrimSpace(mustRun(t, env, "", "transit", "decrypt", "app", ct2)); out != "hello world" {
		t.Fatalf("decrypt rewrapped = %q", out)
	}
}

// TestLeaseCLI drives the lease CLI: create a token (a lease), look it up, then
// revoke the whole prefix.
func TestLeaseCLI(t *testing.T) {
	addr, root := startCLIServer(t)
	env := []string{"KEEPHIPPO_ADDR=" + addr, "KEEPHIPPO_TOKEN=" + root}

	mustRun(t, env, "", "token", "create", "-policy=default", "-ttl=1h")

	listOut := mustRun(t, env, "", "list", "sys/leases/lookup/auth/token/create/")
	suffix := firstKey(listOut)
	if suffix == "" {
		t.Fatalf("no lease listed:\n%s", listOut)
	}
	leaseID := "auth/token/create/" + suffix
	if out := mustRun(t, env, "", "lease", "lookup", leaseID); !strings.Contains(out, "id") {
		t.Fatalf("lease lookup output:\n%s", out)
	}

	mustRun(t, env, "", "lease", "revoke", "-prefix", "auth/token/create/")
	if _, code := runCLI(t, env, "", "list", "sys/leases/lookup/auth/token/create/"); code != 2 {
		t.Fatalf("expected no leases (exit 2) after revoke-prefix, got exit %d", code)
	}
}

// firstKey returns the first data row of a `keys`-style table (skipping the
// "Keys" / "----" header lines).
func firstKey(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "Keys" || strings.HasPrefix(line, "---") {
			continue
		}
		return line
	}
	return ""
}
