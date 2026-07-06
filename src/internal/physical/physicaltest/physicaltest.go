// Package physicaltest provides a shared conformance suite that any
// physical.Backend implementation can run to prove it honors the contract.
package physicaltest

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/jfigge/keephippo/internal/physical"
)

// Exercise runs the backend contract against b, which must start empty.
func Exercise(t *testing.T, b physical.Backend) {
	t.Helper()

	// Missing key returns (nil, nil).
	if got, err := b.Get("nope"); err != nil || got != nil {
		t.Fatalf("Get(missing) = %v, %v; want nil, nil", got, err)
	}

	// Empty list.
	if got, err := b.List(""); err != nil || len(got) != 0 {
		t.Fatalf("List(empty) = %v, %v; want [], nil", got, err)
	}

	put := func(k string, v string) {
		t.Helper()
		if err := b.Put(&physical.Entry{Key: k, Value: []byte(v)}); err != nil {
			t.Fatalf("Put(%q) error: %v", k, err)
		}
	}
	put("a", "1")
	put("b/c", "2")
	put("b/d", "3")
	put("e", "4")

	// Get round-trips the stored value.
	if got, err := b.Get("a"); err != nil || got == nil || !bytes.Equal(got.Value, []byte("1")) {
		t.Fatalf("Get(a) = %v, %v; want value \"1\"", got, err)
	}

	// List at root returns immediate children; sub-prefixes carry a trailing /.
	if got, err := b.List(""); err != nil || !reflect.DeepEqual(got, []string{"a", "b/", "e"}) {
		t.Fatalf("List(\"\") = %v, %v; want [a b/ e]", got, err)
	}
	if got, err := b.List("b/"); err != nil || !reflect.DeepEqual(got, []string{"c", "d"}) {
		t.Fatalf("List(b/) = %v, %v; want [c d]", got, err)
	}

	// Overwrite.
	put("b/c", "22")
	if got, _ := b.Get("b/c"); got == nil || !bytes.Equal(got.Value, []byte("22")) {
		t.Fatalf("Get(b/c) after overwrite = %v; want \"22\"", got)
	}

	// Delete removes the key (and idempotent for missing keys).
	if err := b.Delete("a"); err != nil {
		t.Fatalf("Delete(a) error: %v", err)
	}
	if err := b.Delete("a"); err != nil {
		t.Fatalf("Delete(missing) error: %v", err)
	}
	if got, _ := b.Get("a"); got != nil {
		t.Fatalf("Get(a) after delete = %v; want nil", got)
	}
	if got, _ := b.List(""); !reflect.DeepEqual(got, []string{"b/", "e"}) {
		t.Fatalf("List(\"\") after delete = %v; want [b/ e]", got)
	}
}
