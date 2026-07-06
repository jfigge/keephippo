package command

import (
	"image"
	_ "image/png"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// repoRoot locates the repository root relative to this test file
// (src/internal/command/docs_test.go → ../../.. == repo root).
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine caller path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func readGuide(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "USER_GUIDE.md"))
	if err != nil {
		t.Fatalf("read USER_GUIDE.md: %v", err)
	}
	return string(b)
}

// allCommandPaths walks the cobra tree and returns every command path (e.g.
// "kv put"), skipping hidden and cobra's built-in help/completion commands.
func allCommandPaths() []string {
	var out []string
	var walk func(cmd *cobra.Command, prefix string)
	walk = func(cmd *cobra.Command, prefix string) {
		for _, c := range cmd.Commands() {
			name := c.Name()
			if c.Hidden || name == "help" || name == "completion" {
				continue
			}
			path := strings.TrimSpace(prefix + " " + name)
			out = append(out, path)
			walk(c, path)
		}
	}
	walk(newRootCmd(), "")
	sort.Strings(out)
	return out
}

// TestUserGuideCommandCoverage asserts every CLI command/subcommand has a
// "### `keephippo <path>`" heading in the user guide.
func TestUserGuideCommandCoverage(t *testing.T) {
	guide := readGuide(t)
	var missing []string
	for _, p := range allCommandPaths() {
		heading := "### `keephippo " + p + "`"
		if !strings.Contains(guide, heading) {
			missing = append(missing, heading)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("USER_GUIDE.md is missing %d command heading(s):\n%s", len(missing), strings.Join(missing, "\n"))
	}
}

// TestUserGuideImageDimensions asserts every docs/images/*.png is exactly
// 900×562.
func TestUserGuideImageDimensions(t *testing.T) {
	dir := filepath.Join(repoRoot(t), "docs", "images")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read docs/images: %v", err)
	}
	pngs := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".png") {
			continue
		}
		pngs++
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("open %s: %v", e.Name(), err)
		}
		cfg, _, err := image.DecodeConfig(f)
		_ = f.Close()
		if err != nil {
			t.Fatalf("decode %s: %v", e.Name(), err)
		}
		if cfg.Width != 900 || cfg.Height != 562 {
			t.Errorf("%s is %d×%d; want 900×562", e.Name(), cfg.Width, cfg.Height)
		}
	}
	if pngs == 0 {
		t.Fatal("no PNG images found under docs/images/")
	}
}

var (
	mdImageRe = regexp.MustCompile(`!\[([^\]]*)\]\(([^)]+)\)`)
	mdLinkRe  = regexp.MustCompile(`\[[^\]]+\]\(([^)]+)\)`)
)

// TestUserGuideLinksResolve checks that image references have alt text and
// resolve, that relative markdown links resolve, and that intra-page anchors
// referenced in the guide exist as headings.
func TestUserGuideLinksResolve(t *testing.T) {
	root := repoRoot(t)
	docsDir := filepath.Join(root, "docs")
	guidePath := filepath.Join(docsDir, "USER_GUIDE.md")
	guide := readGuide(t)

	// Images: alt text present and file exists.
	for _, m := range mdImageRe.FindAllStringSubmatch(guide, -1) {
		alt, ref := m[1], m[2]
		if strings.TrimSpace(alt) == "" {
			t.Errorf("image reference %q has empty alt text", ref)
		}
		if !fileExists(filepath.Join(docsDir, ref)) {
			t.Errorf("image %q does not resolve", ref)
		}
	}

	// Anchors available in the guide (GitHub-style slugs of ## / ### headings).
	anchors := headingAnchors(guide)

	for _, m := range mdLinkRe.FindAllStringSubmatch(guide, -1) {
		ref := m[1]
		switch {
		case strings.HasPrefix(ref, "http://"), strings.HasPrefix(ref, "https://"), strings.HasPrefix(ref, "mailto:"):
			continue
		case strings.HasPrefix(ref, "#"):
			if _, ok := anchors[strings.TrimPrefix(ref, "#")]; !ok {
				t.Errorf("intra-page anchor %q has no matching heading", ref)
			}
		default:
			// Relative file link (optionally with an #anchor); check the file.
			path := ref
			if i := strings.IndexByte(path, '#'); i >= 0 {
				path = path[:i]
			}
			if path == "" {
				continue
			}
			if !fileExists(filepath.Join(filepath.Dir(guidePath), path)) {
				t.Errorf("relative link %q does not resolve", ref)
			}
		}
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

var anchorStrip = regexp.MustCompile(`[^a-z0-9 -]`)

// headingAnchors returns the set of GitHub-style anchor slugs for the markdown
// headings in src.
func headingAnchors(src string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, line := range strings.Split(src, "\n") {
		if !strings.HasPrefix(line, "#") {
			continue
		}
		text := strings.TrimLeft(line, "# ")
		slug := strings.ToLower(text)
		slug = anchorStrip.ReplaceAllString(slug, "")
		slug = strings.ReplaceAll(slug, " ", "-")
		out[slug] = struct{}{}
	}
	return out
}
