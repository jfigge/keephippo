package logical

import (
	"strconv"
	"strings"
	"time"
)

// Field helpers for reading request data in backends. Request data arrives as
// decoded JSON (map[string]any), so numbers are float64 and everything may be
// absent; these normalise the common cases.

// FieldString returns data[key] as a string, or "".
func FieldString(data map[string]any, key string) string {
	v, _ := data[key].(string)
	return v
}

// FieldBool returns data[key] as a bool, or def when absent/mistyped. It also
// accepts the string forms "true"/"false" that arrive from CLI key=value input.
func FieldBool(data map[string]any, key string, def bool) bool {
	switch v := data[key].(type) {
	case bool:
		return v
	case string:
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

// FieldInt returns data[key] as an int, or 0.
func FieldInt(data map[string]any, key string) int {
	switch v := data[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}

// FieldStringSlice returns data[key] as a []string, accepting a JSON array or a
// comma-separated string (as the CLI sends).
func FieldStringSlice(data map[string]any, key string) []string {
	switch v := data[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v == "" {
			return nil
		}
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return nil
}

// FieldIntSlice returns data[key] as a []int, accepting a JSON array or a
// comma-separated string. Used for KV v2 {"versions":[1,2,3]}.
func FieldIntSlice(data map[string]any, key string) []int {
	var out []int
	switch v := data[key].(type) {
	case []int:
		return v
	case []any:
		for _, e := range v {
			switch n := e.(type) {
			case float64:
				out = append(out, int(n))
			case int:
				out = append(out, n)
			case string:
				if x, err := strconv.Atoi(n); err == nil {
					out = append(out, x)
				}
			}
		}
	case string:
		for _, p := range strings.Split(v, ",") {
			if x, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
				out = append(out, x)
			}
		}
	}
	return out
}

// FieldDuration returns data[key] as a time.Duration, accepting a Go duration
// string ("30m"), a bare integer number of seconds, or a numeric JSON value.
func FieldDuration(data map[string]any, key string) time.Duration {
	switch v := data[key].(type) {
	case string:
		if v == "" {
			return 0
		}
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Second
		}
	case float64:
		return time.Duration(v) * time.Second
	case int:
		return time.Duration(v) * time.Second
	}
	return 0
}

// FieldMap returns data[key] as a map[string]any, or nil.
func FieldMap(data map[string]any, key string) map[string]any {
	m, _ := data[key].(map[string]any)
	return m
}

// FieldStringMap returns data[key] as a map[string]string (custom metadata).
func FieldStringMap(data map[string]any, key string) map[string]string {
	raw, ok := data[key].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}
