//go:build windows

package audit

import "errors"

// SyslogDevice is unavailable on Windows.
type SyslogDevice struct{}

// NewSyslogDevice returns an error: syslog is not supported on Windows.
func NewSyslogDevice(_ string) (*SyslogDevice, error) {
	return nil, errors.New("the syslog audit device is not supported on Windows")
}

func (d *SyslogDevice) Log(map[string]any) error { return nil }
func (d *SyslogDevice) Close() error             { return nil }
