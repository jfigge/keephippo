//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// TestKVv2CLI drives the KV v2 CLI subcommands through the built binary: version
// detection, versioned put/get, -version reads, metadata, and rollback.
func TestKVv2CLI(t *testing.T) {
	addr, root := startCLIServer(t)
	env := []string{"KEEPHIPPO_ADDR=" + addr, "KEEPHIPPO_TOKEN=" + root}

	mustRun(t, env, "", "secrets", "enable", "-path=kv2", "-version=2", "kv")
	mustRun(t, env, "", "kv", "put", "kv2/app", "user=alice")
	mustRun(t, env, "", "kv", "put", "kv2/app", "user=bob")

	// Latest read → bob.
	if out := mustRun(t, env, "", "kv", "get", "kv2/app"); !strings.Contains(out, "bob") {
		t.Fatalf("kv get latest missing bob:\n%s", out)
	}
	// Historical read → alice.
	if out := mustRun(t, env, "", "kv", "get", "-version=1", "kv2/app"); !strings.Contains(out, "alice") {
		t.Fatalf("kv get -version=1 missing alice:\n%s", out)
	}
	// Metadata reports two versions.
	if out := mustRun(t, env, "", "kv", "metadata", "get", "kv2/app"); !strings.Contains(out, "current_version") {
		t.Fatalf("kv metadata get missing current_version:\n%s", out)
	}
	// Rollback to v1 → new latest reads alice again.
	mustRun(t, env, "", "kv", "rollback", "-version=1", "kv2/app")
	if out := mustRun(t, env, "", "kv", "get", "kv2/app"); !strings.Contains(out, "alice") {
		t.Fatalf("kv get after rollback missing alice:\n%s", out)
	}
	// Soft-delete then get shows no data.
	mustRun(t, env, "", "kv", "delete", "kv2/app")
	if out := mustRun(t, env, "", "kv", "get", "kv2/app"); strings.Contains(out, "alice") {
		t.Fatalf("kv get after delete still shows data:\n%s", out)
	}
}

// TestKVv2VersionOpsCLI covers the version-mutating v2 subcommands through the
// binary: patch (read-modify-write), and delete/undelete/destroy by version.
func TestKVv2VersionOpsCLI(t *testing.T) {
	addr, root := startCLIServer(t)
	env := []string{"KEEPHIPPO_ADDR=" + addr, "KEEPHIPPO_TOKEN=" + root}

	mustRun(t, env, "", "secrets", "enable", "-path=kv2", "-version=2", "kv")
	// Deterministic versions 1,2,3.
	mustRun(t, env, "", "kv", "put", "kv2/rec", "n=1")
	mustRun(t, env, "", "kv", "put", "kv2/rec", "n=2")
	mustRun(t, env, "", "kv", "put", "kv2/rec", "n=3")

	// patch merges a field into a new latest version, preserving existing keys.
	mustRun(t, env, "", "kv", "patch", "kv2/rec", "extra=z")
	if out := mustRun(t, env, "", "kv", "get", "kv2/rec"); !strings.Contains(out, "extra") || !strings.Contains(out, "3") {
		t.Fatalf("patch did not merge:\n%s", out)
	}

	// Soft-delete v2, confirm hidden, then undelete and confirm restored.
	mustRun(t, env, "", "kv", "delete", "-versions=2", "kv2/rec")
	if out := mustRun(t, env, "", "kv", "get", "-version=2", "kv2/rec"); !strings.Contains(out, "no data at this version") {
		t.Fatalf("v2 still readable after delete:\n%s", out)
	}
	mustRun(t, env, "", "kv", "undelete", "-versions=2", "kv2/rec")
	if out := mustRun(t, env, "", "kv", "get", "-version=2", "kv2/rec"); strings.Contains(out, "no data at this version") {
		t.Fatalf("v2 not restored after undelete:\n%s", out)
	}

	// Destroy v1 permanently; its metadata should mark it destroyed.
	mustRun(t, env, "", "kv", "destroy", "-versions=1", "kv2/rec")
	if out := mustRun(t, env, "", "kv", "get", "-version=1", "kv2/rec"); !strings.Contains(out, "destroyed") {
		t.Fatalf("v1 not destroyed:\n%s", out)
	}
}

// TestUserpassLoginCLI drives `login -method=userpass` through the binary and
// confirms the stored token can then access a policy-scoped path.
func TestUserpassLoginCLI(t *testing.T) {
	addr, root := startCLIServer(t)
	rootEnv := []string{"KEEPHIPPO_ADDR=" + addr, "KEEPHIPPO_TOKEN=" + root}

	mustRun(t, rootEnv, "", "secrets", "enable", "-path=kv2", "-version=2", "kv")
	mustRun(t, rootEnv, "", "kv", "put", "kv2/svc", "token=xyz")
	mustRun(t, rootEnv, "", "auth", "enable", "userpass")
	mustRun(t, rootEnv, `path "kv2/*" { capabilities = ["read"] }`, "policy", "write", "reader", "-")
	mustRun(t, rootEnv, "", "write", "auth/userpass/users/carol", "password=pw", "token_policies=reader")

	// Log in as carol through the CLI (isolated HOME → own token helper file).
	home := t.TempDir()
	userEnv := []string{"KEEPHIPPO_ADDR=" + addr, "HOME=" + home}
	if out := mustRun(t, userEnv, "", "login", "-method=userpass", "username=carol", "password=pw"); !strings.Contains(out, "Success") {
		t.Fatalf("login output:\n%s", out)
	}
	// The stored carol token can read the allowed v2 path.
	if out := mustRun(t, userEnv, "", "kv", "get", "kv2/svc"); !strings.Contains(out, "xyz") {
		t.Fatalf("carol kv get missing value:\n%s", out)
	}
	// Wrong password fails (exit non-zero).
	if _, code := runCLI(t, userEnv, "", "login", "-method=userpass", "username=carol", "password=nope"); code == 0 {
		t.Fatal("login with wrong password should fail")
	}
}
