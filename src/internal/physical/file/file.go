// Package file is a durable physical.Backend backed by a single bbolt database.
package file

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"

	"github.com/jfigge/keephippo/internal/physical"
)

// bucket holds every key/value pair. bbolt requires at least one bucket.
var bucket = []byte("keephippo")

// Backend stores data in a bbolt file on disk.
type Backend struct {
	db *bolt.DB
}

var _ physical.Backend = (*Backend)(nil)

// New opens (creating if needed) a bbolt database at path. The parent
// directory is created if it does not exist.
func New(path string) (*Backend, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("physical/file: create dir: %w", err)
		}
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 0})
	if err != nil {
		return nil, fmt.Errorf("physical/file: open %q: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, e := tx.CreateBucketIfNotExists(bucket)
		return e
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("physical/file: init bucket: %w", err)
	}
	return &Backend{db: db}, nil
}

// Close releases the underlying database file.
func (b *Backend) Close() error {
	return b.db.Close()
}

func (b *Backend) Put(entry *physical.Entry) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Put([]byte(entry.Key), entry.Value)
	})
}

func (b *Backend) Get(key string) (*physical.Entry, error) {
	var out *physical.Entry
	err := b.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucket).Get([]byte(key))
		if v == nil {
			return nil
		}
		cp := make([]byte, len(v)) // bbolt values are only valid within the tx
		copy(cp, v)
		out = &physical.Entry{Key: key, Value: cp}
		return nil
	})
	return out, err
}

func (b *Backend) Delete(key string) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Delete([]byte(key))
	})
}

func (b *Backend) List(prefix string) ([]string, error) {
	var keys []string
	err := b.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucket).Cursor()
		p := []byte(prefix)
		for k, _ := c.Seek(p); k != nil && strings.HasPrefix(string(k), prefix); k, _ = c.Next() {
			keys = append(keys, string(k))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return physical.Children(prefix, keys), nil
}
