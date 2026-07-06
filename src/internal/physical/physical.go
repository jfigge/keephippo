package physical

import (
	"sort"
	"strings"
)

// Entry is a single stored key/value pair. Keys are slash-delimited paths.
type Entry struct {
	Key   string
	Value []byte
}

// Backend is a durable key/value store. Implementations must be safe for
// concurrent use. Get returns (nil, nil) when the key is absent.
type Backend interface {
	// Put stores entry, overwriting any existing value at entry.Key.
	Put(entry *Entry) error
	// Get returns the entry at key, or (nil, nil) if it does not exist.
	Get(key string) (*Entry, error)
	// Delete removes key. Deleting a missing key is not an error.
	Delete(key string) error
	// List returns the immediate child names under prefix. A child that is
	// itself a prefix of deeper keys is returned with a trailing "/", per
	// Vault's list semantics. Results are sorted and de-duplicated.
	List(prefix string) ([]string, error)
}

// Children reduces a set of full keys to the immediate child segments under
// prefix, following Vault list semantics: a key "a/b/c" under prefix "a/"
// contributes the child "b/". Results are sorted and de-duplicated.
func Children(prefix string, keys []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		rest := k[len(prefix):]
		if rest == "" {
			continue
		}
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			rest = rest[:i+1] // keep the trailing slash to mark a sub-prefix
		}
		if _, ok := seen[rest]; ok {
			continue
		}
		seen[rest] = struct{}{}
		out = append(out, rest)
	}
	sort.Strings(out)
	return out
}
