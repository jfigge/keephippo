//go:build !windows

package audit

import (
	"encoding/json"
	"log/syslog"
	"sync"
)

// SyslogDevice writes JSON audit records to the local syslog daemon.
type SyslogDevice struct {
	mu sync.Mutex
	w  *syslog.Writer
}

// NewSyslogDevice connects to syslog. tag defaults to "keephippo".
func NewSyslogDevice(tag string) (*SyslogDevice, error) {
	if tag == "" {
		tag = "keephippo"
	}
	w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_AUTH, tag)
	if err != nil {
		return nil, err
	}
	return &SyslogDevice{w: w}, nil
}

func (d *SyslogDevice) Log(record map[string]any) error {
	blob, err := json.Marshal(record)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.w.Info(string(blob))
}

func (d *SyslogDevice) Close() error { return d.w.Close() }
