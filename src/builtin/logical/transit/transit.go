// Package transit implements the transit secrets engine: encryption as a
// service. Named keys never leave the barrier; clients send plaintext and
// receive versioned ciphertext (vault:v<N>:<base64>) and vice-versa, plus
// sign/verify, hmac, and data-key generation. All primitives come from the
// standard library (+ x/crypto/chacha20poly1305) — no home-grown crypto.
package transit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jfigge/keephippo/internal/logical"
)

// Backend is the transit engine over a per-mount storage view.
type Backend struct {
	storage logical.Storage
	nowFn   func() time.Time
}

var _ logical.Backend = (*Backend)(nil)

// New returns a transit backend backed by storage.
func New(storage logical.Storage) *Backend { return &Backend{storage: storage, nowFn: time.Now} }

// keyVersion is the material for one version of a named key.
type keyVersion struct {
	Key         []byte `json:"key"`                  // symmetric key or asymmetric private material
	HMACKey     []byte `json:"hmac_key"`             // per-version key for the hmac endpoint
	PublicKey   []byte `json:"public_key,omitempty"` // asymmetric only
	CreatedTime string `json:"created_time"`
}

// keyPolicy is the stored configuration + versions of a named transit key.
type keyPolicy struct {
	Name                 string             `json:"name"`
	Type                 string             `json:"type"`
	LatestVersion        int                `json:"latest_version"`
	MinDecryptionVersion int                `json:"min_decryption_version"`
	MinEncryptionVersion int                `json:"min_encryption_version"`
	DeletionAllowed      bool               `json:"deletion_allowed"`
	Versions             map[int]keyVersion `json:"versions"`
}

func coded(status int, msg string) error { return &logical.CodedError{Status: status, Message: msg} }

func (b *Backend) HandleRequest(req *logical.Request) (*logical.Response, error) {
	path := req.Path
	switch {
	case path == "keys":
		if req.Operation == logical.ListOperation {
			return b.listKeys()
		}
		return nil, coded(404, "unsupported path")
	case strings.HasPrefix(path, "keys/"):
		return b.keyDispatch(req, strings.TrimPrefix(path, "keys/"))
	case strings.HasPrefix(path, "encrypt/"):
		return b.encrypt(req, strings.TrimPrefix(path, "encrypt/"))
	case strings.HasPrefix(path, "decrypt/"):
		return b.decrypt(req, strings.TrimPrefix(path, "decrypt/"))
	case strings.HasPrefix(path, "rewrap/"):
		return b.rewrap(req, strings.TrimPrefix(path, "rewrap/"))
	case strings.HasPrefix(path, "sign/"):
		return b.sign(req, strings.TrimPrefix(path, "sign/"))
	case strings.HasPrefix(path, "verify/"):
		return b.verify(req, strings.TrimPrefix(path, "verify/"))
	case strings.HasPrefix(path, "hmac/"):
		return b.hmac(req, strings.TrimPrefix(path, "hmac/"))
	case strings.HasPrefix(path, "datakey/"):
		return b.datakey(req, strings.TrimPrefix(path, "datakey/"))
	default:
		return nil, coded(404, fmt.Sprintf("unsupported path %q", path))
	}
}

// --- key management ---

func (b *Backend) keyDispatch(req *logical.Request, rest string) (*logical.Response, error) {
	name, sub, _ := strings.Cut(rest, "/")
	if name == "" {
		return nil, coded(400, "missing key name")
	}
	switch sub {
	case "":
		return b.keyOp(req, name)
	case "rotate":
		return b.rotate(name)
	case "config":
		return b.configKey(req, name)
	default:
		return nil, coded(404, fmt.Sprintf("unsupported path keys/%s", rest))
	}
}

func (b *Backend) keyOp(req *logical.Request, name string) (*logical.Response, error) {
	switch req.Operation {
	case logical.CreateOperation, logical.UpdateOperation:
		return b.createKey(req, name)
	case logical.ReadOperation:
		return b.readKey(name)
	case logical.DeleteOperation:
		return nil, b.deleteKey(name)
	default:
		return nil, coded(405, "unsupported operation")
	}
}

func (b *Backend) createKey(req *logical.Request, name string) (*logical.Response, error) {
	if kp, err := b.load(name); err != nil {
		return nil, err
	} else if kp != nil {
		return b.readKey(name) // idempotent: creating an existing key is a no-op
	}
	typ := logical.FieldString(req.Data, "type")
	if typ == "" {
		typ = typeAES256GCM96
	}
	if !supportedType(typ) {
		return nil, coded(400, fmt.Sprintf("unsupported key type %q", typ))
	}
	kp := &keyPolicy{Name: name, Type: typ, MinDecryptionVersion: 1, MinEncryptionVersion: 0, Versions: map[int]keyVersion{}}
	if err := b.addVersion(kp); err != nil {
		return nil, err
	}
	if err := b.save(kp); err != nil {
		return nil, err
	}
	return b.readKey(name)
}

func (b *Backend) addVersion(kp *keyPolicy) error {
	key, hmacKey, pub, err := newVersionMaterial(kp.Type)
	if err != nil {
		return err
	}
	kp.LatestVersion++
	kp.Versions[kp.LatestVersion] = keyVersion{
		Key: key, HMACKey: hmacKey, PublicKey: pub,
		CreatedTime: b.nowFn().UTC().Format(time.RFC3339),
	}
	return nil
}

func (b *Backend) rotate(name string) (*logical.Response, error) {
	kp, err := b.load(name)
	if err != nil {
		return nil, err
	}
	if kp == nil {
		return nil, coded(404, "no such key")
	}
	if err := b.addVersion(kp); err != nil {
		return nil, err
	}
	if err := b.save(kp); err != nil {
		return nil, err
	}
	return b.readKey(name)
}

func (b *Backend) configKey(req *logical.Request, name string) (*logical.Response, error) {
	kp, err := b.load(name)
	if err != nil {
		return nil, err
	}
	if kp == nil {
		return nil, coded(404, "no such key")
	}
	if _, ok := req.Data["min_decryption_version"]; ok {
		kp.MinDecryptionVersion = logical.FieldInt(req.Data, "min_decryption_version")
	}
	if _, ok := req.Data["min_encryption_version"]; ok {
		kp.MinEncryptionVersion = logical.FieldInt(req.Data, "min_encryption_version")
	}
	if _, ok := req.Data["deletion_allowed"]; ok {
		kp.DeletionAllowed = logical.FieldBool(req.Data, "deletion_allowed", false)
	}
	return nil, b.save(kp)
}

func (b *Backend) readKey(name string) (*logical.Response, error) {
	kp, err := b.load(name)
	if err != nil {
		return nil, err
	}
	if kp == nil {
		return nil, nil // 404
	}
	keys := map[string]any{}
	for ver, kv := range kp.Versions {
		if isAsymmetric(kp.Type) {
			keys[strconv.Itoa(ver)] = map[string]any{
				"creation_time": kv.CreatedTime,
				"public_key":    base64.StdEncoding.EncodeToString(kv.PublicKey),
			}
		} else {
			keys[strconv.Itoa(ver)] = kv.CreatedTime
		}
	}
	return &logical.Response{Data: map[string]any{
		"name":                   kp.Name,
		"type":                   kp.Type,
		"latest_version":         kp.LatestVersion,
		"min_decryption_version": kp.MinDecryptionVersion,
		"min_encryption_version": kp.MinEncryptionVersion,
		"deletion_allowed":       kp.DeletionAllowed,
		"supports_encryption":    isSymmetric(kp.Type),
		"supports_decryption":    isSymmetric(kp.Type),
		"supports_signing":       isAsymmetric(kp.Type),
		"keys":                   keys,
	}}, nil
}

func (b *Backend) deleteKey(name string) error {
	kp, err := b.load(name)
	if err != nil {
		return err
	}
	if kp == nil {
		return nil
	}
	if !kp.DeletionAllowed {
		return coded(400, "deletion is not allowed for this key; set deletion_allowed via .../config")
	}
	return b.storage.Delete(keyStorageKey(name))
}

func (b *Backend) listKeys() (*logical.Response, error) {
	keys, err := b.storage.List("key/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(keys), nil
}

// --- crypto operations ---

func (b *Backend) encrypt(req *logical.Request, name string) (*logical.Response, error) {
	kp, err := b.loadEncryptable(name)
	if err != nil {
		return nil, err
	}
	pt, err := decodeB64(req.Data, "plaintext")
	if err != nil {
		return nil, err
	}
	ver := kp.LatestVersion
	if v := logical.FieldInt(req.Data, "key_version"); v > 0 {
		ver = v
	}
	if ver < kp.MinEncryptionVersion || ver > kp.LatestVersion {
		return nil, coded(400, "invalid key version for encryption")
	}
	blob, err := symEncrypt(kp.Type, kp.Versions[ver].Key, pt)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{
		"ciphertext":  formatCiphertext(ver, blob),
		"key_version": ver,
	}}, nil
}

func (b *Backend) decrypt(req *logical.Request, name string) (*logical.Response, error) {
	kp, err := b.loadEncryptable(name)
	if err != nil {
		return nil, err
	}
	pt, err := b.decryptCiphertext(kp, logical.FieldString(req.Data, "ciphertext"))
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString(pt),
	}}, nil
}

func (b *Backend) rewrap(req *logical.Request, name string) (*logical.Response, error) {
	kp, err := b.loadEncryptable(name)
	if err != nil {
		return nil, err
	}
	pt, err := b.decryptCiphertext(kp, logical.FieldString(req.Data, "ciphertext"))
	if err != nil {
		return nil, err
	}
	blob, err := symEncrypt(kp.Type, kp.Versions[kp.LatestVersion].Key, pt)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{
		"ciphertext":  formatCiphertext(kp.LatestVersion, blob),
		"key_version": kp.LatestVersion,
	}}, nil
}

// decryptCiphertext parses a vault:vN:… ciphertext and decrypts it, enforcing
// min_decryption_version.
func (b *Backend) decryptCiphertext(kp *keyPolicy, ct string) ([]byte, error) {
	ver, blob, err := parseCiphertext(ct)
	if err != nil {
		return nil, err
	}
	if ver < kp.MinDecryptionVersion {
		return nil, coded(400, "ciphertext version is disallowed by policy (below min_decryption_version)")
	}
	kv, ok := kp.Versions[ver]
	if !ok {
		return nil, coded(400, "ciphertext refers to a nonexistent key version")
	}
	pt, err := symDecrypt(kp.Type, kv.Key, blob)
	if err != nil {
		return nil, coded(400, "decryption failed")
	}
	return pt, nil
}

func (b *Backend) sign(req *logical.Request, name string) (*logical.Response, error) {
	kp, err := b.load(name)
	if err != nil {
		return nil, err
	}
	if kp == nil {
		return nil, coded(404, "no such key")
	}
	if !isAsymmetric(kp.Type) {
		return nil, coded(400, "key does not support signing")
	}
	input, err := decodeB64(req.Data, "input")
	if err != nil {
		return nil, err
	}
	ver := kp.LatestVersion
	sig, err := signInput(kp.Type, kp.Versions[ver].Key, input)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{
		"signature":   formatCiphertext(ver, sig),
		"key_version": ver,
	}}, nil
}

func (b *Backend) verify(req *logical.Request, name string) (*logical.Response, error) {
	kp, err := b.load(name)
	if err != nil {
		return nil, err
	}
	if kp == nil {
		return nil, coded(404, "no such key")
	}
	input, err := decodeB64(req.Data, "input")
	if err != nil {
		return nil, err
	}
	valid := false
	if sig := logical.FieldString(req.Data, "signature"); sig != "" && isAsymmetric(kp.Type) {
		ver, raw, perr := parseCiphertext(sig)
		if perr == nil {
			if kv, ok := kp.Versions[ver]; ok {
				valid = verifySig(kp.Type, kv.PublicKey, input, raw)
			}
		}
	} else if h := logical.FieldString(req.Data, "hmac"); h != "" {
		ver, raw, perr := parseCiphertext(h)
		if perr == nil {
			if kv, ok := kp.Versions[ver]; ok {
				valid = hmacEqual(hmacSum(kv.HMACKey, input), raw)
			}
		}
	}
	return &logical.Response{Data: map[string]any{"valid": valid}}, nil
}

func (b *Backend) hmac(req *logical.Request, name string) (*logical.Response, error) {
	kp, err := b.load(name)
	if err != nil {
		return nil, err
	}
	if kp == nil {
		return nil, coded(404, "no such key")
	}
	input, err := decodeB64(req.Data, "input")
	if err != nil {
		return nil, err
	}
	ver := kp.LatestVersion
	sum := hmacSum(kp.Versions[ver].HMACKey, input)
	return &logical.Response{Data: map[string]any{
		"hmac":        formatCiphertext(ver, sum),
		"key_version": ver,
	}}, nil
}

func (b *Backend) datakey(req *logical.Request, rest string) (*logical.Response, error) {
	mode, name, _ := strings.Cut(rest, "/")
	if name == "" {
		return nil, coded(400, "missing key name")
	}
	kp, err := b.loadEncryptable(name)
	if err != nil {
		return nil, err
	}
	dk := make([]byte, 32)
	if _, err := randRead(dk); err != nil {
		return nil, err
	}
	blob, err := symEncrypt(kp.Type, kp.Versions[kp.LatestVersion].Key, dk)
	if err != nil {
		return nil, err
	}
	data := map[string]any{"ciphertext": formatCiphertext(kp.LatestVersion, blob)}
	switch mode {
	case "plaintext":
		data["plaintext"] = base64.StdEncoding.EncodeToString(dk)
	case "wrapped":
		// ciphertext only
	default:
		return nil, coded(400, `datakey type must be "plaintext" or "wrapped"`)
	}
	return &logical.Response{Data: data}, nil
}

// --- helpers ---

func (b *Backend) loadEncryptable(name string) (*keyPolicy, error) {
	kp, err := b.load(name)
	if err != nil {
		return nil, err
	}
	if kp == nil {
		return nil, coded(404, "no such key")
	}
	if !isSymmetric(kp.Type) {
		return nil, coded(400, "key does not support encryption")
	}
	return kp, nil
}

func decodeB64(data map[string]any, field string) ([]byte, error) {
	s := logical.FieldString(data, field)
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, coded(400, fmt.Sprintf("%q must be base64-encoded", field))
	}
	return raw, nil
}

func formatCiphertext(ver int, blob []byte) string {
	return "vault:v" + strconv.Itoa(ver) + ":" + base64.StdEncoding.EncodeToString(blob)
}

func parseCiphertext(s string) (int, []byte, error) {
	if !strings.HasPrefix(s, "vault:v") {
		return 0, nil, coded(400, "invalid ciphertext format")
	}
	rest := s[len("vault:v"):]
	i := strings.IndexByte(rest, ':')
	if i < 0 {
		return 0, nil, coded(400, "invalid ciphertext format")
	}
	ver, err := strconv.Atoi(rest[:i])
	if err != nil || ver < 1 {
		return 0, nil, coded(400, "invalid ciphertext version")
	}
	blob, err := base64.StdEncoding.DecodeString(rest[i+1:])
	if err != nil {
		return 0, nil, coded(400, "invalid ciphertext payload")
	}
	return ver, blob, nil
}

func (b *Backend) load(name string) (*keyPolicy, error) {
	e, err := b.storage.Get(keyStorageKey(name))
	if err != nil || e == nil {
		return nil, err
	}
	var kp keyPolicy
	if err := json.Unmarshal(e.Value, &kp); err != nil {
		return nil, err
	}
	if kp.Versions == nil {
		kp.Versions = map[int]keyVersion{}
	}
	return &kp, nil
}

func (b *Backend) save(kp *keyPolicy) error {
	blob, err := json.Marshal(kp)
	if err != nil {
		return err
	}
	return b.storage.Put(&logical.StorageEntry{Key: keyStorageKey(kp.Name), Value: blob})
}

func keyStorageKey(name string) string { return "key/" + name }
