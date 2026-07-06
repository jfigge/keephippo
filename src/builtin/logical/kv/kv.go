// Package kv implements the KV version 1 (unversioned) secrets engine: a simple
// encrypted key/value store mounted at an arbitrary path.
package kv

import (
	"encoding/json"
	"fmt"

	"github.com/jfigge/keephippo/internal/logical"
)

// Backend is a KV v1 secrets engine over a per-mount storage view.
type Backend struct {
	storage logical.Storage
}

var _ logical.Backend = (*Backend)(nil)

// New returns a KV v1 backend backed by storage.
func New(storage logical.Storage) *Backend {
	return &Backend{storage: storage}
}

// HandleRequest dispatches read/write/delete/list against the mount's storage.
func (b *Backend) HandleRequest(req *logical.Request) (*logical.Response, error) {
	switch req.Operation {
	case logical.ReadOperation:
		return b.read(req.Path)
	case logical.CreateOperation, logical.UpdateOperation:
		return b.write(req.Path, req.Data)
	case logical.DeleteOperation:
		return b.delete(req.Path)
	case logical.ListOperation:
		return b.list(req.Path)
	default:
		return nil, fmt.Errorf("kv: unsupported operation %q", req.Operation)
	}
}

func (b *Backend) read(path string) (*logical.Response, error) {
	e, err := b.storage.Get(path)
	if err != nil {
		return nil, err
	}
	if e == nil {
		return nil, nil // not found → 404
	}
	var data map[string]any
	if err := json.Unmarshal(e.Value, &data); err != nil {
		return nil, fmt.Errorf("kv: corrupt entry at %q: %w", path, err)
	}
	return &logical.Response{Data: data}, nil
}

func (b *Backend) write(path string, data map[string]any) (*logical.Response, error) {
	if data == nil {
		data = map[string]any{}
	}
	blob, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	if err := b.storage.Put(&logical.StorageEntry{Key: path, Value: blob}); err != nil {
		return nil, err
	}
	return nil, nil // success, no content → 204
}

func (b *Backend) delete(path string) (*logical.Response, error) {
	if err := b.storage.Delete(path); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *Backend) list(path string) (*logical.Response, error) {
	keys, err := b.storage.List(path)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(keys), nil
}
