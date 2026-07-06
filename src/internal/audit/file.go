package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// FileDevice writes newline-delimited JSON audit records to a file (append-only)
// or, for the special paths "stdout"/"discard", to those sinks.
type FileDevice struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer
}

// NewFileDevice opens path for appending. The special values "stdout" and
// "discard" select those writers instead of a file.
func NewFileDevice(path string) (*FileDevice, error) {
	switch path {
	case "":
		return nil, fmt.Errorf("audit file device requires file_path")
	case "stdout":
		return &FileDevice{w: os.Stdout}, nil
	case "discard":
		return &FileDevice{w: io.Discard}, nil
	default:
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return nil, err
		}
		return &FileDevice{w: f, closer: f}, nil
	}
}

// Log appends the record as one JSON line. A write error propagates so the core
// can fail the request closed.
func (d *FileDevice) Log(record map[string]any) error {
	blob, err := json.Marshal(record)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, err := d.w.Write(append(blob, '\n')); err != nil {
		return err
	}
	return nil
}

// Close closes the underlying file (a no-op for stdout/discard).
func (d *FileDevice) Close() error {
	if d.closer != nil {
		return d.closer.Close()
	}
	return nil
}
