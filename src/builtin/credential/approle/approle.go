// Package approle implements the AppRole auth method: a role_id + secret_id pair
// (machine credentials) that exchange for a policy-scoped token. secret_ids are
// stored only as SHA-256 hashes and compared in constant time; they honour a TTL
// and a use count.
//
// Paths (relative to the auth/<mount>/ prefix):
//
//	role                       (LIST)              list roles
//	role/<name>                (C/R/U/D)           manage a role
//	role/<name>/role-id        (read/update)       read or set the role_id
//	role/<name>/secret-id      (update)            generate a secret_id
//	login                      (create/update)     exchange role_id+secret_id for a token
package approle

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jfigge/keephippo/internal/logical"
)

// Backend is the AppRole auth method over a per-mount storage view.
type Backend struct {
	storage logical.Storage
	nowFn   func() time.Time
}

var (
	_ logical.Backend         = (*Backend)(nil)
	_ logical.Unauthenticated = (*Backend)(nil)
)

// New returns an AppRole backend backed by storage.
func New(storage logical.Storage) *Backend {
	return &Backend{storage: storage, nowFn: time.Now}
}

// role is the stored per-role configuration.
type role struct {
	RoleID          string   `json:"role_id"`
	Policies        []string `json:"policies"`
	TokenTTL        int64    `json:"token_ttl"`          // seconds; 0 = system default
	SecretIDTTL     int64    `json:"secret_id_ttl"`      // seconds; 0 = no expiry
	SecretIDNumUses int      `json:"secret_id_num_uses"` // 0 = unlimited
	BindSecretID    bool     `json:"bind_secret_id"`
}

// secretIDEntry is a stored, hashed secret_id with its lifecycle limits.
type secretIDEntry struct {
	HashHex      string `json:"hash_hex"`
	ExpireTime   int64  `json:"expire_time"` // unix seconds; 0 = never
	NumUses      int    `json:"num_uses"`    // 0 = unlimited
	CreationTime int64  `json:"creation_time"`
}

// IsUnauthenticated reports whether path is the login path.
func (b *Backend) IsUnauthenticated(_ logical.Operation, path string) bool {
	return path == "login"
}

func (b *Backend) HandleRequest(req *logical.Request) (*logical.Response, error) {
	path := req.Path
	switch {
	case path == "role":
		if req.Operation == logical.ListOperation {
			return b.listRoles()
		}
		return nil, &logical.CodedError{Status: 404, Message: "unsupported path"}
	case path == "login":
		return b.login(req)
	case strings.HasPrefix(path, "role/"):
		return b.roleDispatch(req, strings.TrimPrefix(path, "role/"))
	default:
		return nil, &logical.CodedError{Status: 404, Message: fmt.Sprintf("unsupported path %q", path)}
	}
}

// roleDispatch splits role/<name>[/subresource].
func (b *Backend) roleDispatch(req *logical.Request, rest string) (*logical.Response, error) {
	name, sub, _ := strings.Cut(rest, "/")
	if name == "" {
		return nil, &logical.CodedError{Status: 400, Message: "missing role name"}
	}
	switch sub {
	case "":
		return b.roleOp(req, name)
	case "role-id":
		return b.roleID(req, name)
	case "secret-id":
		return b.generateSecretID(req, name)
	default:
		return nil, &logical.CodedError{Status: 404, Message: fmt.Sprintf("unsupported path role/%s", rest)}
	}
}

func (b *Backend) roleOp(req *logical.Request, name string) (*logical.Response, error) {
	switch req.Operation {
	case logical.CreateOperation, logical.UpdateOperation:
		return b.writeRole(req, name)
	case logical.ReadOperation:
		return b.readRole(name)
	case logical.DeleteOperation:
		return nil, b.deleteRole(name)
	default:
		return nil, &logical.CodedError{Status: 405, Message: "unsupported operation"}
	}
}

func (b *Backend) writeRole(req *logical.Request, name string) (*logical.Response, error) {
	r, err := b.loadRole(name)
	if err != nil {
		return nil, err
	}
	created := r == nil
	if created {
		r = &role{BindSecretID: true}
		rid, err := randString()
		if err != nil {
			return nil, err
		}
		r.RoleID = rid
	}

	if pols := logical.FieldStringSlice(req.Data, "token_policies"); len(pols) > 0 {
		r.Policies = pols
	} else if pols := logical.FieldStringSlice(req.Data, "policies"); len(pols) > 0 {
		r.Policies = pols
	}
	if v := logical.FieldString(req.Data, "role_id"); v != "" {
		r.RoleID = v
	}
	if _, ok := req.Data["token_ttl"]; ok {
		r.TokenTTL = int64(logical.FieldDuration(req.Data, "token_ttl") / time.Second)
	}
	if _, ok := req.Data["secret_id_ttl"]; ok {
		r.SecretIDTTL = int64(logical.FieldDuration(req.Data, "secret_id_ttl") / time.Second)
	}
	if _, ok := req.Data["secret_id_num_uses"]; ok {
		r.SecretIDNumUses = logical.FieldInt(req.Data, "secret_id_num_uses")
	}
	if _, ok := req.Data["bind_secret_id"]; ok {
		r.BindSecretID = logical.FieldBool(req.Data, "bind_secret_id", true)
	}

	if err := b.saveRole(name, r); err != nil {
		return nil, err
	}
	// Maintain the role_id → name reverse index for login.
	return nil, b.storage.Put(&logical.StorageEntry{Key: roleIDIndexKey(r.RoleID), Value: []byte(name)})
}

func (b *Backend) readRole(name string) (*logical.Response, error) {
	r, err := b.loadRole(name)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, nil // 404
	}
	return &logical.Response{Data: map[string]any{
		"role_id":            r.RoleID,
		"token_policies":     r.Policies,
		"policies":           r.Policies,
		"token_ttl":          r.TokenTTL,
		"secret_id_ttl":      r.SecretIDTTL,
		"secret_id_num_uses": r.SecretIDNumUses,
		"bind_secret_id":     r.BindSecretID,
	}}, nil
}

func (b *Backend) deleteRole(name string) error {
	r, err := b.loadRole(name)
	if err != nil {
		return err
	}
	if r == nil {
		return nil
	}
	_ = b.storage.Delete(roleIDIndexKey(r.RoleID))
	// Purge issued secret_ids for this role.
	if hashes, err := b.storage.List(secretIDPrefix(name)); err == nil {
		for _, h := range hashes {
			_ = b.storage.Delete(secretIDPrefix(name) + h)
		}
	}
	return b.storage.Delete(roleKey(name))
}

func (b *Backend) roleID(req *logical.Request, name string) (*logical.Response, error) {
	r, err := b.loadRole(name)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, nil
	}
	switch req.Operation {
	case logical.ReadOperation:
		return &logical.Response{Data: map[string]any{"role_id": r.RoleID}}, nil
	case logical.CreateOperation, logical.UpdateOperation:
		newID := logical.FieldString(req.Data, "role_id")
		if newID == "" {
			return nil, &logical.CodedError{Status: 400, Message: "missing role_id"}
		}
		_ = b.storage.Delete(roleIDIndexKey(r.RoleID))
		r.RoleID = newID
		if err := b.saveRole(name, r); err != nil {
			return nil, err
		}
		return nil, b.storage.Put(&logical.StorageEntry{Key: roleIDIndexKey(newID), Value: []byte(name)})
	default:
		return nil, &logical.CodedError{Status: 405, Message: "unsupported operation"}
	}
}

func (b *Backend) generateSecretID(req *logical.Request, name string) (*logical.Response, error) {
	r, err := b.loadRole(name)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, &logical.CodedError{Status: 404, Message: fmt.Sprintf("role %q does not exist", name)}
	}
	secretID, err := randString()
	if err != nil {
		return nil, err
	}
	now := b.nowFn().Unix()
	entry := &secretIDEntry{
		HashHex:      hashHex(secretID),
		NumUses:      r.SecretIDNumUses,
		CreationTime: now,
	}
	if r.SecretIDTTL > 0 {
		entry.ExpireTime = now + r.SecretIDTTL
	}
	blob, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}
	if err := b.storage.Put(&logical.StorageEntry{Key: secretIDPrefix(name) + entry.HashHex, Value: blob}); err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{
		"secret_id":          secretID,
		"secret_id_accessor": entry.HashHex,
		"secret_id_ttl":      r.SecretIDTTL,
		"secret_id_num_uses": r.SecretIDNumUses,
	}}, nil
}

func (b *Backend) login(req *logical.Request) (*logical.Response, error) {
	roleID := logical.FieldString(req.Data, "role_id")
	if roleID == "" {
		return nil, &logical.CodedError{Status: 400, Message: "missing role_id"}
	}
	name, err := b.roleNameForID(roleID)
	if err != nil {
		return nil, err
	}
	r, err := b.loadRole(name)
	if err != nil {
		return nil, err
	}
	if name == "" || r == nil {
		return nil, &logical.CodedError{Status: 400, Message: "invalid role or secret id"}
	}

	if r.BindSecretID {
		secretID := logical.FieldString(req.Data, "secret_id")
		if secretID == "" {
			return nil, &logical.CodedError{Status: 400, Message: "missing secret_id"}
		}
		if err := b.consumeSecretID(name, secretID); err != nil {
			return nil, err
		}
	}

	return &logical.Response{Auth: &logical.Auth{
		Policies:      r.Policies,
		LeaseDuration: r.TokenTTL,
		Renewable:     true,
		DisplayName:   "approle-" + name,
		Metadata:      map[string]string{"role_name": name},
	}}, nil
}

// consumeSecretID verifies a secret_id against the role, enforcing expiry and
// use count and decrementing/deleting it. The comparison is constant-time.
func (b *Backend) consumeSecretID(name, secretID string) error {
	h := hashHex(secretID)
	e, err := b.storage.Get(secretIDPrefix(name) + h)
	if err != nil {
		return err
	}
	invalid := &logical.CodedError{Status: 400, Message: "invalid role or secret id"}
	if e == nil {
		return invalid
	}
	var entry secretIDEntry
	if err := json.Unmarshal(e.Value, &entry); err != nil {
		return err
	}
	// Defense-in-depth constant-time compare against the stored hash.
	if subtle.ConstantTimeCompare([]byte(entry.HashHex), []byte(h)) != 1 {
		return invalid
	}
	if entry.ExpireTime != 0 && b.nowFn().Unix() > entry.ExpireTime {
		_ = b.storage.Delete(secretIDPrefix(name) + h)
		return invalid
	}
	if entry.NumUses > 0 {
		entry.NumUses--
		if entry.NumUses == 0 {
			return b.storage.Delete(secretIDPrefix(name) + h)
		}
		blob, err := json.Marshal(&entry)
		if err != nil {
			return err
		}
		return b.storage.Put(&logical.StorageEntry{Key: secretIDPrefix(name) + h, Value: blob})
	}
	return nil
}

func (b *Backend) roleNameForID(roleID string) (string, error) {
	e, err := b.storage.Get(roleIDIndexKey(roleID))
	if err != nil || e == nil {
		return "", err
	}
	return string(e.Value), nil
}

func (b *Backend) listRoles() (*logical.Response, error) {
	keys, err := b.storage.List("role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(keys), nil
}

func (b *Backend) loadRole(name string) (*role, error) {
	e, err := b.storage.Get(roleKey(name))
	if err != nil || e == nil {
		return nil, err
	}
	var r role
	if err := json.Unmarshal(e.Value, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (b *Backend) saveRole(name string, r *role) error {
	blob, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return b.storage.Put(&logical.StorageEntry{Key: roleKey(name), Value: blob})
}

func roleKey(name string) string        { return "role/" + name }
func roleIDIndexKey(id string) string   { return "role_id/" + hashHex(id) }
func secretIDPrefix(name string) string { return "secret_id/" + name + "/" }

func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randString() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
