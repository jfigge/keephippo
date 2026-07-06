package version

import (
	"strings"
	"testing"
)

func TestShortReturnsVersion(t *testing.T) {
	orig := Version
	t.Cleanup(func() { Version = orig })

	Version = "v9.9.9"
	if got := Short(); got != "v9.9.9" {
		t.Fatalf("Short() = %q, want %q", got, "v9.9.9")
	}
}

func TestInfoContainsAllFields(t *testing.T) {
	orig := [4]string{Version, Commit, Branch, BuildTime}
	t.Cleanup(func() { Version, Commit, Branch, BuildTime = orig[0], orig[1], orig[2], orig[3] })

	Version, Branch, Commit, BuildTime = "v1.2.3", "main", "abc1234", "2026-07-05T00:00:00Z"

	info := Info()
	for _, want := range []string{"v1.2.3", "main", "abc1234", "2026-07-05T00:00:00Z", "platform:", "go:"} {
		if !strings.Contains(info, want) {
			t.Errorf("Info() missing %q; got:\n%s", want, info)
		}
	}
}
