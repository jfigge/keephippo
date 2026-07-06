// Package cubbyhole implements the cubbyhole secrets engine: a private
// key/value store scoped to the calling token. Each token sees only its own
// data, and that data is destroyed when the token is revoked. Response wrapping
// stores the wrapped payload in a wrapping token's cubbyhole.
package cubbyhole

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jfigge/keephippo/internal/logical"
)

// Backend is the cubbyhole engine over a per-mount storage view. Entries are
// namespaced by a hash of the client token.
type Backend struct {
	storage logical.Storage
}

var _ logical.Backend = (*Backend)(nil)

// New returns a cubbyhole backend backed by storage.
func New(storage logical.Storage) *Backend { return &Backend{storage: storage} }

func (b *Backend) HandleRequest(req *logical.Request) (*logical.Response, error) {
	if req.ClientToken == "" {
		return nil, &logical.CodedError{Status: 400, Message: "cubbyhole operations require a token"}
	}
	key := scopeKey(req.ClientToken, req.Path)
	switch req.Operation {
	case logical.ReadOperation:
		e, err := b.storage.Get(key)
		if err != nil || e == nil {
			return nil, err // nil → 404
		}
		var data map[string]any
		if err := json.Unmarshal(e.Value, &data); err != nil {
			return nil, err
		}
		return &logical.Response{Data: data}, nil
	case logical.CreateOperation, logical.UpdateOperation:
		data := req.Data
		if data == nil {
			data = map[string]any{}
		}
		blob, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		return nil, b.storage.Put(&logical.StorageEntry{Key: key, Value: blob})
	case logical.DeleteOperation:
		return nil, b.storage.Delete(key)
	case logical.ListOperation:
		keys, err := b.storage.List(key)
		if err != nil {
			return nil, err
		}
		return logical.ListResponse(keys), nil
	default:
		return nil, fmt.Errorf("cubbyhole: unsupported operation %q", req.Operation)
	}
}

// Purge deletes every entry belonging to token (called when a token is revoked).
func Purge(storage logical.Storage, token string) error {
	return clear(storage, tokenPrefix(token))
}

func clear(storage logical.Storage, prefix string) error {
	children, err := storage.List(prefix)
	if err != nil {
		return err
	}
	for _, ch := range children {
		full := prefix + ch
		if strings.HasSuffix(ch, "/") {
			if err := clear(storage, full); err != nil {
				return err
			}
		} else if err := storage.Delete(full); err != nil {
			return err
		}
	}
	return nil
}

func tokenPrefix(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:]) + "/"
}

func scopeKey(token, path string) string { return tokenPrefix(token) + path }
