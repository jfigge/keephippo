package command

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var attrRefRe = regexp.MustCompile(`(?:href|src)="([^"]+)"`)

// resolveSiteRef maps an href/src on an HTML page to a file path under the site
// root, or returns ("", false) for external/anchor references that need no
// local file.
func resolveSiteRef(siteRoot, pageDir, ref string) (string, bool) {
	// Strip query/fragment.
	if i := strings.IndexAny(ref, "#?"); i >= 0 {
		ref = ref[:i]
	}
	switch {
	case ref == "":
		return "", false
	case strings.HasPrefix(ref, "http://"), strings.HasPrefix(ref, "https://"),
		strings.HasPrefix(ref, "mailto:"), strings.HasPrefix(ref, "//"):
		return "", false
	}
	var p string
	if strings.HasPrefix(ref, "/") {
		p = filepath.Join(siteRoot, filepath.FromSlash(ref))
	} else {
		p = filepath.Join(pageDir, filepath.FromSlash(ref))
	}
	// A directory or trailing-slash link serves its index.html.
	if strings.HasSuffix(ref, "/") {
		p = filepath.Join(p, "index.html")
	} else if fi, err := os.Stat(p); err == nil && fi.IsDir() {
		p = filepath.Join(p, "index.html")
	}
	return p, true
}

// TestWebsiteInternalLinks crawls the built website/ and asserts every internal
// link and asset reference resolves to a real file.
func TestWebsiteInternalLinks(t *testing.T) {
	siteRoot := filepath.Join(repoRoot(t), "website")
	if _, err := os.Stat(siteRoot); err != nil {
		t.Fatalf("website/ not built: %v (run `make site`)", err)
	}

	var htmlFiles []string
	err := filepath.WalkDir(siteRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".html") {
			htmlFiles = append(htmlFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk website: %v", err)
	}
	if len(htmlFiles) < 5 {
		t.Fatalf("expected the site's pages, found %d html files", len(htmlFiles))
	}

	for _, page := range htmlFiles {
		body, err := os.ReadFile(page)
		if err != nil {
			t.Fatalf("read %s: %v", page, err)
		}
		pageDir := filepath.Dir(page)
		for _, m := range attrRefRe.FindAllStringSubmatch(string(body), -1) {
			target, local := resolveSiteRef(siteRoot, pageDir, m[1])
			if !local {
				continue
			}
			if _, err := os.Stat(target); err != nil {
				rel, _ := filepath.Rel(siteRoot, page)
				t.Errorf("%s: reference %q does not resolve (%s)", rel, m[1], target)
			}
		}
	}
}

// TestWebsiteRequiredFiles asserts the site includes its required top-level
// assets and the generated docs + versions files.
func TestWebsiteRequiredFiles(t *testing.T) {
	siteRoot := filepath.Join(repoRoot(t), "website")
	required := []string{
		"index.html", "features.html", "downloads.html", "vs-vault.html", "privacy.html",
		"site.css", "robots.txt", "sitemap.xml", "CNAME", "og-image.png", "versions.json",
		"docs/index.html", "docs/command-reference.html",
	}
	for _, f := range required {
		if _, err := os.Stat(filepath.Join(siteRoot, filepath.FromSlash(f))); err != nil {
			t.Errorf("missing required site file: %s", f)
		}
	}
	// CNAME must name the custom domain.
	if b, err := os.ReadFile(filepath.Join(siteRoot, "CNAME")); err != nil || strings.TrimSpace(string(b)) != "keephippo.com" {
		t.Errorf("CNAME should contain keephippo.com, got %q (%v)", string(b), err)
	}
}
