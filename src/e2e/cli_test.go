//go:build e2e

package e2e

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var binPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "kh-bin")
	if err != nil {
		panic(err)
	}
	binPath = filepath.Join(dir, "keephippo")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/keephippo")
	build.Dir = ".." // module root (src/); this package lives in src/e2e
	if out, err := build.CombinedOutput(); err != nil {
		panic(fmt.Sprintf("build binary: %v\n%s", err, out))
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func waitReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(addr + "/v1/sys/seal-status")
		if err == nil {
			_ = resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server at %s never became ready", addr)
}

// runCLI runs the built binary and returns combined output and exit code.
func runCLI(t *testing.T, env []string, stdin string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = append(os.Environ(), env...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return string(out), ee.ExitCode()
		}
		t.Fatalf("run %v: %v", args, err)
	}
	return string(out), 0
}

func mustRun(t *testing.T, env []string, stdin string, args ...string) string {
	t.Helper()
	out, code := runCLI(t, env, stdin, args...)
	if code != 0 {
		t.Fatalf("expected success but got exit %d for %v:\n%s", code, args, out)
	}
	return out
}

func field(out, label string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, label) {
			return strings.TrimSpace(strings.SplitN(line, label, 2)[1])
		}
	}
	return ""
}

// startCLIServer boots a file-backed server via the binary, initializes and
// unseals it, and returns the address + root token.
func startCLIServer(t *testing.T) (string, string) {
	t.Helper()
	port := freePort(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.hcl")
	conf := fmt.Sprintf("storage \"file\" { path = %q }\nlistener \"tcp\" { address = \"127.0.0.1:%d\" }\n", dir, port)
	if err := os.WriteFile(cfg, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := exec.Command(binPath, "server", "--config", cfg)
	if err := srv.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		_ = srv.Process.Kill()
		_ = srv.Wait()
	})

	addr := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitReady(t, addr)

	env := []string{"KEEPHIPPO_ADDR=" + addr}
	initOut := mustRun(t, env, "", "operator", "init", "-key-shares=1", "-key-threshold=1")
	key := field(initOut, "Unseal Key 1:")
	root := field(initOut, "Initial Root Token:")
	if key == "" || root == "" {
		t.Fatalf("could not parse init output:\n%s", initOut)
	}
	mustRun(t, env, "", "operator", "unseal", key)
	return addr, root
}

// TestScriptedSessionCLI runs the full DoD session entirely through the binary.
func TestScriptedSessionCLI(t *testing.T) {
	addr, root := startCLIServer(t)
	home := t.TempDir() // isolate the token helper (~/.keephippo-token)
	base := []string{"KEEPHIPPO_ADDR=" + addr, "HOME=" + home}

	// login stores the token; later commands rely on the stored token.
	mustRun(t, base, "", "login", root)
	mustRun(t, base, "", "secrets", "enable", "-path=secret", "kv")
	mustRun(t, base, "", "kv", "put", "secret/foo", "a=b")

	if out := mustRun(t, base, "", "kv", "get", "secret/foo"); !strings.Contains(out, "a") || !strings.Contains(out, "b") {
		t.Fatalf("kv get output missing a=b:\n%s", out)
	}

	mustRun(t, base, `path "secret/*" { capabilities = ["read"] }`, "policy", "write", "app", "-")

	tokenOut := mustRun(t, base, "", "token", "create", "-policy=app")
	tok := field(tokenOut, "token ")
	if tok == "" {
		t.Fatalf("could not parse created token:\n%s", tokenOut)
	}
	mustRun(t, base, "", "token", "revoke", tok)
}

// TestFormatJSON asserts --format=json emits the Vault-compatible envelope.
func TestFormatJSON(t *testing.T) {
	addr, root := startCLIServer(t)
	env := []string{"KEEPHIPPO_ADDR=" + addr, "KEEPHIPPO_TOKEN=" + root}
	mustRun(t, env, "", "secrets", "enable", "-path=secret", "kv")
	mustRun(t, env, "", "kv", "put", "secret/j", "k=v")

	out := mustRun(t, env, "", "kv", "get", "-format=json", "secret/j")
	var env2 map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &env2); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	for _, k := range []string{"request_id", "lease_id", "renewable", "lease_duration", "data", "wrap_info", "warnings", "auth"} {
		if _, ok := env2[k]; !ok {
			t.Errorf("json envelope missing key %q", k)
		}
	}
	var data struct {
		K string `json:"k"`
	}
	if err := json.Unmarshal(env2["data"], &data); err != nil || data.K != "v" {
		t.Errorf("json data = %s; want k=v", env2["data"])
	}
}

// TestExitCodes checks Vault-style exit codes.
func TestExitCodes(t *testing.T) {
	addr, root := startCLIServer(t)
	env := []string{"KEEPHIPPO_ADDR=" + addr, "KEEPHIPPO_TOKEN=" + root}
	mustRun(t, env, "", "secrets", "enable", "-path=secret", "kv")

	// Missing value → exit 2.
	if _, code := runCLI(t, env, "", "kv", "get", "secret/nope"); code != 2 {
		t.Errorf("kv get missing exit = %d; want 2", code)
	}
	// Unknown flag → usage error → exit 2.
	if _, code := runCLI(t, env, "", "kv", "get", "--nonsense", "secret/x"); code != 2 {
		t.Errorf("bad flag exit = %d; want 2", code)
	}
	// Permission denied (no token) → exit 1.
	noTok := []string{"KEEPHIPPO_ADDR=" + addr, "HOME=" + t.TempDir()}
	if _, code := runCLI(t, noTok, "", "kv", "get", "secret/x"); code != 1 {
		t.Errorf("no-token exit = %d; want 1", code)
	}
}
