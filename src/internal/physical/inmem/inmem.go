// Package inmem is an in-memory physical.Backend for -dev mode and tests.
// It is not durable: all data is lost when the process exits.
package inmem

import (
	"sync"

	"github.com/jfigge/keephippo/internal/physical"
)

// Backend is a concurrency-safe, in-memory key/value store.
type Backend struct {
	mu   sync.RWMutex
	data map[string][]byte
}

// New returns an empty in-memory backend.
func New() *Backend {
	return &Backend{data: make(map[string][]byte)}
}

var _ physical.Backend = (*Backend)(nil)

func (b *Backend) Put(entry *physical.Entry) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	v := make([]byte, len(entry.Value))
	copy(v, entry.Value)
	b.data[entry.Key] = v
	return nil
}

func (b *Backend) Get(key string) (*physical.Entry, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	v, ok := b.data[key]
	if !ok {
		return nil, nil
	}
	out := make([]byte, len(v))
	copy(out, v)
	return &physical.Entry{Key: key, Value: out}, nil
}

func (b *Backend) Delete(key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.data, key)
	return nil
}

func (b *Backend) List(prefix string) ([]string, error) {
	b.mu.RLock()
	keys := make([]string, 0, len(b.data))
	for k := range b.data {
		keys = append(keys, k)
	}
	b.mu.RUnlock()
	return physical.Children(prefix, keys), nil
}
