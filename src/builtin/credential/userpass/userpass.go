// Package userpass implements the userpass auth method: username + password
// credentials that exchange for a policy-scoped token. Passwords are stored only
// as bcrypt hashes; verification is via bcrypt's constant-time comparison.
//
// Paths (relative to the auth/<mount>/ prefix):
//
//	users            (LIST)              list usernames
//	users/<name>     (C/R/U/D)           manage a user (alias: user/<name>)
//	login/<name>     (create/update)     exchange password for a token
package userpass

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/jfigge/keephippo/internal/logical"
)

// Backend is the userpass auth method over a per-mount storage view.
type Backend struct {
	storage logical.Storage
}

var (
	_ logical.Backend         = (*Backend)(nil)
	_ logical.Unauthenticated = (*Backend)(nil)
)

// New returns a userpass backend backed by storage.
func New(storage logical.Storage) *Backend { return &Backend{storage: storage} }

// user is the stored per-username record. The password is kept only as a bcrypt
// hash — never in cleartext.
type user struct {
	PasswordHash []byte   `json:"password_hash"`
	Policies     []string `json:"policies"`
	TokenTTL     int64    `json:"token_ttl"`     // seconds; 0 = system default
	TokenMaxTTL  int64    `json:"token_max_ttl"` // seconds; 0 = unlimited
}

// IsUnauthenticated reports whether path is a login path (reachable without a
// token). Everything else (user management) requires a token + ACL.
func (b *Backend) IsUnauthenticated(_ logical.Operation, path string) bool {
	return path == "login" || strings.HasPrefix(path, "login/")
}

func (b *Backend) HandleRequest(req *logical.Request) (*logical.Response, error) {
	path := req.Path
	switch {
	case path == "users" || path == "user":
		if req.Operation == logical.ListOperation {
			return b.listUsers()
		}
		return nil, &logical.CodedError{Status: 404, Message: "unsupported path"}
	case strings.HasPrefix(path, "users/"):
		return b.userOp(req, strings.TrimPrefix(path, "users/"))
	case strings.HasPrefix(path, "user/"):
		return b.userOp(req, strings.TrimPrefix(path, "user/"))
	case strings.HasPrefix(path, "login/"):
		return b.login(req, strings.TrimPrefix(path, "login/"))
	default:
		return nil, &logical.CodedError{Status: 404, Message: fmt.Sprintf("unsupported path %q", path)}
	}
}

func (b *Backend) userOp(req *logical.Request, name string) (*logical.Response, error) {
	if name == "" {
		return nil, &logical.CodedError{Status: 400, Message: "missing username"}
	}
	switch req.Operation {
	case logical.CreateOperation, logical.UpdateOperation:
		return b.writeUser(req, name)
	case logical.ReadOperation:
		return b.readUser(name)
	case logical.DeleteOperation:
		return nil, b.storage.Delete(userKey(name))
	case logical.ListOperation:
		return b.listUsers()
	default:
		return nil, &logical.CodedError{Status: 405, Message: "unsupported operation"}
	}
}

func (b *Backend) writeUser(req *logical.Request, name string) (*logical.Response, error) {
	u, err := b.loadUser(name)
	if err != nil {
		return nil, err
	}
	if u == nil {
		u = &user{}
	}

	// Password: required on create, optional on update (keeps the existing hash).
	if pw := logical.FieldString(req.Data, "password"); pw != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		u.PasswordHash = hash
	} else if u.PasswordHash == nil {
		return nil, &logical.CodedError{Status: 400, Message: "missing password"}
	}

	// Policies: accept token_policies or policies (Vault accepts both).
	if pols := logical.FieldStringSlice(req.Data, "token_policies"); len(pols) > 0 {
		u.Policies = pols
	} else if pols := logical.FieldStringSlice(req.Data, "policies"); len(pols) > 0 {
		u.Policies = pols
	}
	if _, ok := req.Data["token_ttl"]; ok {
		u.TokenTTL = int64(logical.FieldDuration(req.Data, "token_ttl") / time.Second)
	}
	if _, ok := req.Data["token_max_ttl"]; ok {
		u.TokenMaxTTL = int64(logical.FieldDuration(req.Data, "token_max_ttl") / time.Second)
	}
	return nil, b.saveUser(name, u)
}

func (b *Backend) readUser(name string) (*logical.Response, error) {
	u, err := b.loadUser(name)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, nil // 404
	}
	// Never expose the password hash.
	return &logical.Response{Data: map[string]any{
		"token_policies": u.Policies,
		"policies":       u.Policies,
		"token_ttl":      u.TokenTTL,
		"token_max_ttl":  u.TokenMaxTTL,
	}}, nil
}

func (b *Backend) listUsers() (*logical.Response, error) {
	keys, err := b.storage.List("user/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(keys), nil
}

func (b *Backend) login(req *logical.Request, name string) (*logical.Response, error) {
	if name == "" {
		return nil, &logical.CodedError{Status: 400, Message: "missing username"}
	}
	u, err := b.loadUser(name)
	if err != nil {
		return nil, err
	}
	pw := logical.FieldString(req.Data, "password")
	// Always run a bcrypt comparison to keep the timing uniform whether or not
	// the user exists (bcrypt.CompareHashAndPassword is constant-time).
	hash := u.hashOrDummy()
	if bcrypt.CompareHashAndPassword(hash, []byte(pw)) != nil || u == nil {
		return nil, &logical.CodedError{Status: 400, Message: "invalid username or password"}
	}
	return &logical.Response{Auth: &logical.Auth{
		Policies:      u.Policies,
		LeaseDuration: u.TokenTTL,
		Renewable:     true,
		DisplayName:   "userpass-" + name,
		Metadata:      map[string]string{"username": name},
		Alias:         name,
	}}, nil
}

// hashOrDummy returns the user's hash, or a fixed bcrypt hash of a random-ish
// string when the user is nil, so a missing user costs the same as a wrong
// password (mitigating username enumeration via timing).
func (u *user) hashOrDummy() []byte {
	if u != nil && u.PasswordHash != nil {
		return u.PasswordHash
	}
	// bcrypt hash of "x" at DefaultCost; the compare will fail but take real time.
	return []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")
}

func (b *Backend) loadUser(name string) (*user, error) {
	e, err := b.storage.Get(userKey(name))
	if err != nil || e == nil {
		return nil, err
	}
	var u user
	if err := json.Unmarshal(e.Value, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

func (b *Backend) saveUser(name string, u *user) error {
	blob, err := json.Marshal(u)
	if err != nil {
		return err
	}
	return b.storage.Put(&logical.StorageEntry{Key: userKey(name), Value: blob})
}

func userKey(name string) string { return "user/" + name }
