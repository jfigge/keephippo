package transit_test

import (
	"encoding/base64"
	"testing"

	"github.com/jfigge/keephippo/builtin/logical/transit"
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

func req(op logical.Operation, path string, data map[string]any, st logical.Storage) *logical.Request {
	return &logical.Request{Operation: op, Path: path, Data: data, Storage: st}
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func mustDo(t *testing.T, b *transit.Backend, op logical.Operation, path string, data map[string]any, st logical.Storage) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(req(op, path, data, st))
	if err != nil {
		t.Fatalf("%s %s: %v", op, path, err)
	}
	return resp
}

func TestTransitEncryptDecryptRotateRewrap(t *testing.T) {
	for _, typ := range []string{"aes256-gcm96", "chacha20-poly1305"} {
		t.Run(typ, func(t *testing.T) {
			st := newMem()
			b := transit.New(st)
			mustDo(t, b, logical.UpdateOperation, "keys/k", map[string]any{"type": typ}, st)

			// Encrypt at v1.
			enc := mustDo(t, b, logical.UpdateOperation, "encrypt/k", map[string]any{"plaintext": b64("hello")}, st)
			ct1, _ := enc.Data["ciphertext"].(string)
			if ct1 == "" || ct1[:8] != "vault:v1" {
				t.Fatalf("ciphertext = %q", ct1)
			}

			// Decrypt round-trips.
			dec := mustDo(t, b, logical.UpdateOperation, "decrypt/k", map[string]any{"ciphertext": ct1}, st)
			if got := decode(t, dec.Data["plaintext"]); got != "hello" {
				t.Fatalf("decrypt = %q", got)
			}

			// Rotate → v2; old ciphertext still decrypts.
			mustDo(t, b, logical.UpdateOperation, "keys/k/rotate", nil, st)
			dec = mustDo(t, b, logical.UpdateOperation, "decrypt/k", map[string]any{"ciphertext": ct1}, st)
			if got := decode(t, dec.Data["plaintext"]); got != "hello" {
				t.Fatalf("post-rotate decrypt of v1 = %q", got)
			}

			// New encrypt uses v2.
			enc2 := mustDo(t, b, logical.UpdateOperation, "encrypt/k", map[string]any{"plaintext": b64("world")}, st)
			if ct2, _ := enc2.Data["ciphertext"].(string); ct2[:8] != "vault:v2" {
				t.Fatalf("encrypt after rotate = %q", ct2)
			}

			// Rewrap upgrades v1 ciphertext to v2.
			rw := mustDo(t, b, logical.UpdateOperation, "rewrap/k", map[string]any{"ciphertext": ct1}, st)
			ct1b, _ := rw.Data["ciphertext"].(string)
			if ct1b[:8] != "vault:v2" {
				t.Fatalf("rewrap = %q", ct1b)
			}
			dec = mustDo(t, b, logical.UpdateOperation, "decrypt/k", map[string]any{"ciphertext": ct1b}, st)
			if got := decode(t, dec.Data["plaintext"]); got != "hello" {
				t.Fatalf("decrypt rewrapped = %q", got)
			}

			// Raise min_decryption_version to 2 → v1 ciphertext now rejected.
			mustDo(t, b, logical.UpdateOperation, "keys/k/config", map[string]any{"min_decryption_version": 2}, st)
			if _, err := b.HandleRequest(req(logical.UpdateOperation, "decrypt/k", map[string]any{"ciphertext": ct1}, st)); err == nil {
				t.Fatal("v1 ciphertext decrypted despite min_decryption_version=2")
			}
		})
	}
}

func TestTransitSignVerify(t *testing.T) {
	for _, typ := range []string{"ed25519", "ecdsa-p256"} {
		t.Run(typ, func(t *testing.T) {
			st := newMem()
			b := transit.New(st)
			mustDo(t, b, logical.UpdateOperation, "keys/s", map[string]any{"type": typ}, st)

			sig := mustDo(t, b, logical.UpdateOperation, "sign/s", map[string]any{"input": b64("message")}, st)
			sigStr, _ := sig.Data["signature"].(string)
			if sigStr == "" {
				t.Fatal("empty signature")
			}

			ok := mustDo(t, b, logical.UpdateOperation, "verify/s",
				map[string]any{"input": b64("message"), "signature": sigStr}, st)
			if ok.Data["valid"] != true {
				t.Fatalf("valid signature not verified: %v", ok.Data)
			}
			bad := mustDo(t, b, logical.UpdateOperation, "verify/s",
				map[string]any{"input": b64("tampered"), "signature": sigStr}, st)
			if bad.Data["valid"] != false {
				t.Fatal("tampered message verified")
			}

			// Encryption is not supported on signing keys.
			if _, err := b.HandleRequest(req(logical.UpdateOperation, "encrypt/s", map[string]any{"plaintext": b64("x")}, st)); err == nil {
				t.Fatal("encrypt on a signing key should fail")
			}
		})
	}
}

func TestTransitHMAC(t *testing.T) {
	st := newMem()
	b := transit.New(st)
	mustDo(t, b, logical.UpdateOperation, "keys/h", map[string]any{"type": "aes256-gcm96"}, st)

	h := mustDo(t, b, logical.UpdateOperation, "hmac/h", map[string]any{"input": b64("data")}, st)
	hmacStr, _ := h.Data["hmac"].(string)
	ok := mustDo(t, b, logical.UpdateOperation, "verify/h", map[string]any{"input": b64("data"), "hmac": hmacStr}, st)
	if ok.Data["valid"] != true {
		t.Fatalf("hmac not verified: %v", ok.Data)
	}
	bad := mustDo(t, b, logical.UpdateOperation, "verify/h", map[string]any{"input": b64("other"), "hmac": hmacStr}, st)
	if bad.Data["valid"] != false {
		t.Fatal("wrong input verified against hmac")
	}
}

func TestTransitDatakey(t *testing.T) {
	st := newMem()
	b := transit.New(st)
	mustDo(t, b, logical.UpdateOperation, "keys/dk", map[string]any{"type": "aes256-gcm96"}, st)

	pt := mustDo(t, b, logical.UpdateOperation, "datakey/plaintext/dk", nil, st)
	plain, _ := pt.Data["plaintext"].(string)
	ct, _ := pt.Data["ciphertext"].(string)
	if plain == "" || ct == "" {
		t.Fatalf("datakey missing fields: %v", pt.Data)
	}
	// The wrapped ciphertext decrypts back to the plaintext data key.
	dec := mustDo(t, b, logical.UpdateOperation, "decrypt/dk", map[string]any{"ciphertext": ct}, st)
	if dec.Data["plaintext"] != plain {
		t.Fatalf("datakey ciphertext did not round-trip")
	}

	// wrapped mode omits the plaintext.
	w := mustDo(t, b, logical.UpdateOperation, "datakey/wrapped/dk", nil, st)
	if _, ok := w.Data["plaintext"]; ok {
		t.Fatal("wrapped datakey leaked plaintext")
	}
}

func decode(t *testing.T, v any) string {
	t.Helper()
	s, _ := v.(string)
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("plaintext not base64: %q", s)
	}
	return string(raw)
}
