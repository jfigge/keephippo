// Package totp implements the TOTP secrets engine (RFC 6238): named keys hold a
// shared secret and generate/validate time-based one-time codes. Codes are
// computed with the standard library's HMAC + SHA1/256/512.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"net/url"
	"strings"
	"time"

	"github.com/jfigge/keephippo/internal/logical"
)

// Backend is the TOTP engine over a per-mount storage view.
type Backend struct {
	storage logical.Storage
	nowFn   func() time.Time
}

var _ logical.Backend = (*Backend)(nil)

// New returns a TOTP backend backed by storage.
func New(storage logical.Storage) *Backend { return &Backend{storage: storage, nowFn: time.Now} }

// keyEntry is the stored per-key configuration.
type keyEntry struct {
	Secret      []byte `json:"secret"` // raw secret bytes
	Algorithm   string `json:"algorithm"`
	Digits      int    `json:"digits"`
	Period      int    `json:"period"`
	Issuer      string `json:"issuer"`
	AccountName string `json:"account_name"`
}

func coded(status int, msg string) error { return &logical.CodedError{Status: status, Message: msg} }

func (b *Backend) HandleRequest(req *logical.Request) (*logical.Response, error) {
	path := req.Path
	switch {
	case path == "keys":
		if req.Operation == logical.ListOperation {
			keys, err := b.storage.List("key/")
			if err != nil {
				return nil, err
			}
			return logical.ListResponse(keys), nil
		}
		return nil, coded(404, "unsupported path")
	case strings.HasPrefix(path, "keys/"):
		return b.keyOp(req, strings.TrimPrefix(path, "keys/"))
	case strings.HasPrefix(path, "code/"):
		return b.codeOp(req, strings.TrimPrefix(path, "code/"))
	default:
		return nil, coded(404, fmt.Sprintf("unsupported path %q", path))
	}
}

func (b *Backend) keyOp(req *logical.Request, name string) (*logical.Response, error) {
	switch req.Operation {
	case logical.CreateOperation, logical.UpdateOperation:
		return b.createKey(req, name)
	case logical.ReadOperation:
		return b.readKey(name)
	case logical.DeleteOperation:
		return nil, b.storage.Delete(keyStorageKey(name))
	default:
		return nil, coded(405, "unsupported operation")
	}
}

func (b *Backend) createKey(req *logical.Request, name string) (*logical.Response, error) {
	k := &keyEntry{
		Algorithm:   normalizeAlgorithm(logical.FieldString(req.Data, "algorithm")),
		Digits:      orDefault(logical.FieldInt(req.Data, "digits"), 6),
		Period:      orDefault(logical.FieldInt(req.Data, "period"), 30),
		Issuer:      logical.FieldString(req.Data, "issuer"),
		AccountName: logical.FieldString(req.Data, "account_name"),
	}
	if k.Digits != 6 && k.Digits != 8 {
		return nil, coded(400, "digits must be 6 or 8")
	}

	generate := logical.FieldBool(req.Data, "generate", false)
	resp := &logical.Response{}
	switch {
	case generate:
		k.Secret = make([]byte, 20)
		if _, err := rand.Read(k.Secret); err != nil {
			return nil, err
		}
		u := k.otpauthURL(name)
		resp.Data = map[string]any{"url": u, "barcode": ""}
	default:
		key := logical.FieldString(req.Data, "key")
		if key == "" {
			return nil, coded(400, "either generate=true or a base32 key is required")
		}
		secret, err := decodeBase32(key)
		if err != nil {
			return nil, coded(400, "key must be valid base32")
		}
		k.Secret = secret
	}
	if err := b.saveKey(name, k); err != nil {
		return nil, err
	}
	return resp, nil
}

func (b *Backend) readKey(name string) (*logical.Response, error) {
	k, err := b.loadKey(name)
	if err != nil || k == nil {
		return nil, err
	}
	// Never expose the secret.
	return &logical.Response{Data: map[string]any{
		"account_name": k.AccountName,
		"algorithm":    k.Algorithm,
		"digits":       k.Digits,
		"period":       k.Period,
		"issuer":       k.Issuer,
	}}, nil
}

func (b *Backend) codeOp(req *logical.Request, name string) (*logical.Response, error) {
	k, err := b.loadKey(name)
	if err != nil {
		return nil, err
	}
	if k == nil {
		return nil, coded(404, "no such key")
	}
	switch req.Operation {
	case logical.ReadOperation:
		return &logical.Response{Data: map[string]any{"code": k.codeAt(b.nowFn().Unix(), 0)}}, nil
	case logical.CreateOperation, logical.UpdateOperation:
		provided := logical.FieldString(req.Data, "code")
		valid := k.validate(provided, b.nowFn().Unix())
		return &logical.Response{Data: map[string]any{"valid": valid}}, nil
	default:
		return nil, coded(405, "unsupported operation")
	}
}

// --- TOTP core (RFC 6238) ---

func (k *keyEntry) codeAt(unix int64, offsetSteps int64) string {
	counter := unix/int64(k.Period) + offsetSteps
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(hashFor(k.Algorithm), k.Secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) | (uint32(sum[off+2]) << 8) | uint32(sum[off+3])
	mod := uint32(1)
	for i := 0; i < k.Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", k.Digits, bin%mod)
}

// validate accepts the code for the current step or the adjacent steps (±1) to
// tolerate clock skew, using a constant-time comparison.
func (k *keyEntry) validate(code string, unix int64) bool {
	if code == "" {
		return false
	}
	for _, off := range []int64{0, -1, 1} {
		if hmac.Equal([]byte(k.codeAt(unix, off)), []byte(code)) {
			return true
		}
	}
	return false
}

func (k *keyEntry) otpauthURL(name string) string {
	label := name
	if k.AccountName != "" {
		label = k.AccountName
	}
	if k.Issuer != "" {
		label = k.Issuer + ":" + label
	}
	q := url.Values{}
	q.Set("secret", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(k.Secret))
	q.Set("algorithm", k.Algorithm)
	q.Set("digits", fmt.Sprintf("%d", k.Digits))
	q.Set("period", fmt.Sprintf("%d", k.Period))
	if k.Issuer != "" {
		q.Set("issuer", k.Issuer)
	}
	return "otpauth://totp/" + url.PathEscape(label) + "?" + q.Encode()
}

func hashFor(algorithm string) func() hash.Hash {
	switch algorithm {
	case "SHA256":
		return sha256.New
	case "SHA512":
		return sha512.New
	default:
		return sha1.New
	}
}

func normalizeAlgorithm(a string) string {
	switch strings.ToUpper(a) {
	case "SHA256":
		return "SHA256"
	case "SHA512":
		return "SHA512"
	default:
		return "SHA1"
	}
}

func decodeBase32(s string) ([]byte, error) {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	return base32.StdEncoding.DecodeString(s)
}

func orDefault(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func (b *Backend) loadKey(name string) (*keyEntry, error) {
	e, err := b.storage.Get(keyStorageKey(name))
	if err != nil || e == nil {
		return nil, err
	}
	var k keyEntry
	if err := json.Unmarshal(e.Value, &k); err != nil {
		return nil, err
	}
	return &k, nil
}

func (b *Backend) saveKey(name string, k *keyEntry) error {
	blob, err := json.Marshal(k)
	if err != nil {
		return err
	}
	return b.storage.Put(&logical.StorageEntry{Key: keyStorageKey(name), Value: blob})
}

func keyStorageKey(name string) string { return "key/" + name }
