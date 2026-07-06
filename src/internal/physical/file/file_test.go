package file_test

import (
	"path/filepath"
	"testing"

	"github.com/jfigge/keephippo/internal/physical"
	"github.com/jfigge/keephippo/internal/physical/file"
	"github.com/jfigge/keephippo/internal/physical/physicaltest"
)

func TestFileBackend(t *testing.T) {
	b, err := file.New(filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	physicaltest.Exercise(t, b)
}

func TestFileBackendPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")

	b1, err := file.New(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := b1.Put(&physical.Entry{Key: "k", Value: []byte("v")}); err != nil {
		t.Fatalf("put: %v", err)
	}
	_ = b1.Close()

	b2, err := file.New(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = b2.Close() })
	got, err := b2.Get("k")
	if err != nil || got == nil || string(got.Value) != "v" {
		t.Fatalf("Get(k) after reopen = %v, %v; want \"v\"", got, err)
	}
}
