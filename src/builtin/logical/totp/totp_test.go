package totp

import (
	"testing"
	"time"

	"github.com/jfigge/keephippo/internal/logical"
	"github.com/jfigge/keephippo/internal/physical"
)

type memStorage struct{ m map[string][]byte }

func newMem() *memStorage { return &memStorage{m: map[string][]byte{}} }

func (s *memStorage) Get(k string) (*logical.StorageEntry, error) {
	v, ok := s.m[k]
	if !ok {
		return nil, nil
	}
	return &logical.StorageEntry{Key: k, Value: v}, nil
}
func (s *memStorage) Put(e *logical.StorageEntry) error { s.m[e.Key] = e.Value; return nil }
func (s *memStorage) Delete(k string) error             { delete(s.m, k); return nil }
func (s *memStorage) List(prefix string) ([]string, error) {
	keys := make([]string, 0, len(s.m))
	for k := range s.m {
		keys = append(keys, k)
	}
	return physical.Children(prefix, keys), nil
}

// TestRFC6238Vectors checks the SHA1/256/512 test vectors from RFC 6238 App. B.
func TestRFC6238Vectors(t *testing.T) {
	cases := []struct {
		algo   string
		secret string
		want   string
	}{
		{"SHA1", "12345678901234567890", "94287082"},
		{"SHA256", "12345678901234567890123456789012", "46119246"},
		{"SHA512", "1234567890123456789012345678901234567890123456789012345678901234", "90693936"},
	}
	for _, tc := range cases {
		k := &keyEntry{Secret: []byte(tc.secret), Algorithm: tc.algo, Digits: 8, Period: 30}
		if got := k.codeAt(59, 0); got != tc.want {
			t.Errorf("%s T=59: code=%s want %s", tc.algo, got, tc.want)
		}
	}
}

func TestTOTPGenerateAndValidate(t *testing.T) {
	st := newMem()
	b := New(st)
	fixed := time.Unix(1_700_000_000, 0)
	b.nowFn = func() time.Time { return fixed }

	// Generate a key → returns an otpauth URL, never the secret.
	resp, err := b.HandleRequest(&logical.Request{
		Operation: logical.UpdateOperation, Path: "keys/login",
		Data: map[string]any{"generate": true, "issuer": "keephippo", "account_name": "bob"}, Storage: st,
	})
	if err != nil || resp == nil {
		t.Fatalf("create: %v %v", resp, err)
	}
	if u, _ := resp.Data["url"].(string); u == "" || u[:8] != "otpauth:" {
		t.Fatalf("bad otpauth url: %v", resp.Data["url"])
	}

	// Read must not expose the secret.
	rd, _ := b.HandleRequest(&logical.Request{Operation: logical.ReadOperation, Path: "keys/login", Storage: st})
	if _, leaked := rd.Data["key"]; leaked {
		t.Fatal("read leaked the secret")
	}
	if _, leaked := rd.Data["secret"]; leaked {
		t.Fatal("read leaked the secret")
	}

	// Generate the current code and validate it.
	code, err := b.HandleRequest(&logical.Request{Operation: logical.ReadOperation, Path: "code/login", Storage: st})
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	current, _ := code.Data["code"].(string)
	if len(current) != 6 {
		t.Fatalf("code = %q, want 6 digits", current)
	}
	valid, _ := b.HandleRequest(&logical.Request{
		Operation: logical.UpdateOperation, Path: "code/login",
		Data: map[string]any{"code": current}, Storage: st,
	})
	if valid.Data["valid"] != true {
		t.Fatalf("current code did not validate: %v", valid.Data)
	}
	// A wrong code is rejected.
	bad, _ := b.HandleRequest(&logical.Request{
		Operation: logical.UpdateOperation, Path: "code/login",
		Data: map[string]any{"code": "000000"}, Storage: st,
	})
	if bad.Data["valid"] != false {
		t.Fatal("wrong code validated")
	}
}

func TestTOTPProvidedKey(t *testing.T) {
	st := newMem()
	b := New(st)
	// base32 of "12345678901234567890" (RFC SHA1 secret) is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
	if _, err := b.HandleRequest(&logical.Request{
		Operation: logical.UpdateOperation, Path: "keys/imported",
		Data: map[string]any{"key": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "digits": 8}, Storage: st,
	}); err != nil {
		t.Fatalf("import: %v", err)
	}
	k, _ := b.loadKey("imported")
	if k == nil || string(k.Secret) != "12345678901234567890" {
		t.Fatalf("imported secret mismatch: %q", k.Secret)
	}
	if got := k.codeAt(59, 0); got != "94287082" {
		t.Fatalf("imported key code = %s", got)
	}
}
