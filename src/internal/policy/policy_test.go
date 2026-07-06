package policy_test

import (
	"reflect"
	"testing"

	"github.com/jfigge/keephippo/internal/policy"
)

func mustParse(t *testing.T, name, src string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse(name, src)
	if err != nil {
		t.Fatalf("parse %q: %v", name, err)
	}
	return p
}

func TestACLTruthTable(t *testing.T) {
	pol := mustParse(t, "app", `
path "secret/data/app/*"      { capabilities = ["read", "list"] }
path "secret/data/app/secret" { capabilities = ["deny"] }
path "secret/data/shared"     { capabilities = ["read", "update"] }
`)
	acl := policy.NewACL([]*policy.Policy{pol})

	cases := []struct {
		path string
		cap  policy.Capability
		want bool
	}{
		{"secret/data/app/foo", policy.Read, true},
		{"secret/data/app/foo", policy.List, true},
		{"secret/data/app/foo", policy.Update, false},
		{"secret/data/app/secret", policy.Read, false}, // exact deny beats glob read
		{"secret/data/shared", policy.Read, true},
		{"secret/data/shared", policy.Update, true},
		{"secret/data/shared", policy.Delete, false},
		{"secret/data/other", policy.Read, false}, // default deny
		{"sys/mounts", policy.Read, false},
	}
	for _, c := range cases {
		if got := acl.Allowed(c.path, c.cap); got != c.want {
			t.Errorf("Allowed(%q, %q) = %v; want %v", c.path, c.cap, got, c.want)
		}
	}
}

func TestRootACL(t *testing.T) {
	acl := policy.NewACL([]*policy.Policy{{Name: "root"}})
	if !acl.Root() {
		t.Fatal("root not detected")
	}
	if !acl.Allowed("anything/at/all", policy.Delete) {
		t.Fatal("root denied")
	}
	if !acl.HasSudo("sys/seal") {
		t.Fatal("root lacks sudo")
	}
	if got := acl.Capabilities("x"); !reflect.DeepEqual(got, []string{"root"}) {
		t.Fatalf("root caps = %v", got)
	}
}

func TestPlusSegment(t *testing.T) {
	acl := policy.NewACL([]*policy.Policy{mustParse(t, "p", `path "secret/+/config" { capabilities = ["read"] }`)})
	if !acl.Allowed("secret/a/config", policy.Read) {
		t.Error("should match a single segment")
	}
	if acl.Allowed("secret/a/b/config", policy.Read) {
		t.Error("should not match two segments")
	}
	if acl.Allowed("secret/config", policy.Read) {
		t.Error("should not match zero segments")
	}
}

func TestSudoGating(t *testing.T) {
	withSudo := policy.NewACL([]*policy.Policy{mustParse(t, "p", `path "sys/seal" { capabilities = ["update", "sudo"] }`)})
	if !withSudo.HasSudo("sys/seal") {
		t.Error("sudo not granted")
	}
	noSudo := policy.NewACL([]*policy.Policy{mustParse(t, "p2", `path "sys/seal" { capabilities = ["update"] }`)})
	if noSudo.HasSudo("sys/seal") {
		t.Error("sudo should not be granted")
	}
}

func TestCapabilitiesList(t *testing.T) {
	acl := policy.NewACL([]*policy.Policy{mustParse(t, "p", `path "secret/data/app/*" { capabilities = ["read","list"] }`)})
	if got := acl.Capabilities("secret/data/app/x"); !reflect.DeepEqual(got, []string{"list", "read"}) {
		t.Fatalf("caps = %v", got)
	}
	if got := acl.Capabilities("other"); !reflect.DeepEqual(got, []string{"deny"}) {
		t.Fatalf("caps = %v", got)
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := policy.Parse("bad", `path "x" { capabilities = ["frobnicate"] }`); err == nil {
		t.Error("expected error for unknown capability")
	}
	if _, err := policy.Parse("bad", `path "x" {`); err == nil {
		t.Error("expected parse error for malformed HCL")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(`path "secret/*" { capabilities = ["read"] }`)
	f.Add(`path "a" { capabilities = ["deny"] }`)
	f.Add(``)
	f.Add(`path`)
	f.Add(`{{{`)
	f.Fuzz(func(t *testing.T, src string) {
		// Parsing arbitrary input must never panic; a successful parse must
		// evaluate without panicking either.
		if p, err := policy.Parse("fuzz", src); err == nil && p != nil {
			acl := policy.NewACL([]*policy.Policy{p})
			_ = acl.Allowed("some/path", policy.Read)
		}
	})
}
