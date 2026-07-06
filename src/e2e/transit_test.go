//go:build e2e

package e2e

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/jfigge/keephippo/api"
)

// TestTransitWorkflowOverHTTP drives the full transit DoD: encrypt/decrypt
// round-trip, decrypt of old ciphertext after rotation, rewrap upgrading the
// version, and sign/verify.
func TestTransitWorkflowOverHTTP(t *testing.T) {
	url, root := newUnsealedServer(t)
	rc := mustClient(t, url, root)

	if _, err := rc.Do(http.MethodPost, "/v1/sys/mounts/transit", map[string]any{"type": "transit"}); err != nil {
		t.Fatalf("mount transit: %v", err)
	}
	if _, err := rc.Do(http.MethodPost, "/v1/transit/keys/app", map[string]any{"type": "aes256-gcm96"}); err != nil {
		t.Fatalf("create key: %v", err)
	}

	secret := "top-secret-payload"
	enc, err := rc.Do(http.MethodPost, "/v1/transit/encrypt/app",
		map[string]any{"plaintext": base64.StdEncoding.EncodeToString([]byte(secret))})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ct, _ := enc.Data["ciphertext"].(string)
	if !strings.HasPrefix(ct, "vault:v1:") {
		t.Fatalf("ciphertext = %q", ct)
	}

	if got := decryptTransit(t, rc, "app", ct); got != secret {
		t.Fatalf("decrypt = %q; want %q", got, secret)
	}

	// Rotate; the v1 ciphertext must still decrypt.
	if _, err := rc.Do(http.MethodPost, "/v1/transit/keys/app/rotate", nil); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if got := decryptTransit(t, rc, "app", ct); got != secret {
		t.Fatalf("post-rotate decrypt = %q", got)
	}

	// Rewrap upgrades the ciphertext to v2, still decrypting to the same plaintext.
	rw, err := rc.Do(http.MethodPost, "/v1/transit/rewrap/app", map[string]any{"ciphertext": ct})
	if err != nil {
		t.Fatalf("rewrap: %v", err)
	}
	ct2, _ := rw.Data["ciphertext"].(string)
	if !strings.HasPrefix(ct2, "vault:v2:") {
		t.Fatalf("rewrapped ciphertext = %q", ct2)
	}
	if got := decryptTransit(t, rc, "app", ct2); got != secret {
		t.Fatalf("decrypt rewrapped = %q", got)
	}

	// Sign / verify with an ed25519 key.
	if _, err := rc.Do(http.MethodPost, "/v1/transit/keys/sig", map[string]any{"type": "ed25519"}); err != nil {
		t.Fatalf("create sig key: %v", err)
	}
	msg := base64.StdEncoding.EncodeToString([]byte("authentic message"))
	sig, err := rc.Do(http.MethodPost, "/v1/transit/sign/sig", map[string]any{"input": msg})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigStr, _ := sig.Data["signature"].(string)
	v, err := rc.Do(http.MethodPost, "/v1/transit/verify/sig", map[string]any{"input": msg, "signature": sigStr})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.Data["valid"] != true {
		t.Fatalf("valid signature not verified: %v", v.Data)
	}
	// A tampered message fails verification.
	bad, _ := rc.Do(http.MethodPost, "/v1/transit/verify/sig",
		map[string]any{"input": base64.StdEncoding.EncodeToString([]byte("forged")), "signature": sigStr})
	if bad.Data["valid"] != false {
		t.Fatal("tampered message verified")
	}
}

func decryptTransit(t *testing.T, rc *api.Client, key, ct string) string {
	t.Helper()
	resp, err := rc.Do(http.MethodPost, "/v1/transit/decrypt/"+key, map[string]any{"ciphertext": ct})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	enc, _ := resp.Data["plaintext"].(string)
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("plaintext not base64: %q", enc)
	}
	return string(raw)
}
