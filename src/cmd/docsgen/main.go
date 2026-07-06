// Command docsgen renders the user-guide images under docs/images/ at exactly
// 900×562 px: CLI examples as terminal-style captures (real command output) and
// the web console screens as styled panels that mirror src/web/app.css. It is a
// dev tool run via `make docs-images`; the generated PNGs are committed.
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

const (
	imgW = 900
	imgH = 562
)

func main() {
	root, err := repoRoot()
	if err != nil {
		fatal(err)
	}
	outDir := filepath.Join(root, "docs", "images")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fatal(err)
	}

	// CLI terminal captures (real output).
	for name, cap := range cliCaptures {
		save(outDir, name, terminal(cap.title, cap.body))
	}
	// Web console screens.
	iconDir := filepath.Join(root, "src", "web", "icons")
	save(outDir, "ui-login", uiLogin(iconDir))
	save(outDir, "ui-secrets", uiSecrets())
	save(outDir, "ui-policies", uiPolicies())
	save(outDir, "ui-console", uiConsole())
	save(outDir, "ui-about", uiAbout(iconDir))

	// Marketing OG image for the website (1200×630).
	webDir := filepath.Join(root, "website")
	if err := os.MkdirAll(webDir, 0o755); err == nil {
		save(webDir, "og-image", ogImage(iconDir))
	}

	fmt.Printf("wrote %d images to %s\n", len(cliCaptures)+5, outDir)
}

// ogImage renders the 1200×630 social-share card from the badge + branding.
func ogImage(iconDir string) *image.RGBA {
	const w, h = 1200, 630
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(img, img.Bounds(), &image.Uniform{uiBg}, image.Point{}, draw.Src)
	// subtle top accent bar
	fillRect(img, 0, 0, w, 6, uiAccent)
	drawIcon(img, iconDir, "256x256.png", 120, 190)
	text(img, 430, 300, "keephippo", uiText)
	text(img, 430, 340, "A from-scratch, Vault-compatible secrets manager.", uiMuted)
	text(img, 430, 372, "Secrets engines - auth methods - policies - transit - web console.", uiMuted)
	text(img, 430, 420, "keephippo.com", uiGreen)
	return img
}

// ---- CLI captures (normalized real output) ----

type capture struct{ title, body string }

var cliCaptures = map[string]capture{
	"cli-status": {"keephippo status", `$ keephippo status
Key             Value
---             -----
Seal Type       shamir
Initialized     true
Sealed          false
Total Shares    1
Threshold       1
Version         v0.2.0
Storage Type    inmem`},

	"cli-secrets-list": {"keephippo secrets list", `$ keephippo secrets list
Path            Type
----            ----
secret/         kv
transit/        transit`},

	"cli-kv-put": {"keephippo kv put", `$ keephippo kv put secret/myapp/db username=admin password=s3cr3t
Success! Data written to: secret/myapp/db`},

	"cli-kv-get": {"keephippo kv get", `$ keephippo kv get secret/myapp/db
Key                 Value
---                 -----
password            s3cr3t
username            admin`},

	"cli-token-create": {"keephippo token create", `$ keephippo token create -policy=default -ttl=1h
Key                 Value
---                 -----
token               kh.W4Flu8abSL8Ihw2tsg-Sf3Pw...
token_accessor      iIvqN4Gf2zTLtKYVSmQ4m30nQ...
token_duration      3600
token_renewable     true
token_policies      [default]`},

	"cli-transit": {"keephippo transit", `$ keephippo transit encrypt app "launch codes"
vault:v1:P7YuX/G0dInbZTwQOjAYWAVGgq44I7n0vAsUMxJK6Vd+DTcALnp28w==

$ keephippo transit decrypt app vault:v1:P7YuX/G0dInbZTwQ...
launch codes`},

	"cli-read-json": {"keephippo read -format=json", `$ keephippo read secret/myapp/db -format=json
{
  "request_id": "94b73bcd-cbd6-4bec-b7d8-296136f08e6d",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "password": "s3cr3t",
    "username": "admin"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}`},

	"cli-unwrap": {"keephippo unwrap", `$ keephippo -wrap-ttl=120s read secret/myapp/db
Key                    Value
---                    -----
wrapping_token         kh.idgsb4_fI2SNaY_ecPuGj1J...
wrapping_token_ttl     120

$ keephippo unwrap kh.idgsb4_fI2SNaY_ecPuGj1J...
Key                 Value
---                 -----
password            s3cr3t
username            admin`},
}

// terminal renders a dark terminal panel with the given command output.
func terminal(title, body string) *image.RGBA {
	img := canvas(hexc("#0e1116"))
	fillRect(img, 0, 0, imgW, 34, hexc("#171b21"))
	fillRect(img, 16, 13, 24, 21, hexc("#ff6b6b"))
	fillRect(img, 32, 13, 40, 21, hexc("#f6c445"))
	fillRect(img, 48, 13, 56, 21, hexc("#3fb950"))
	text(img, 74, 22, title, hexc("#8b97a7"))

	y := 58
	for _, line := range strings.Split(body, "\n") {
		col := hexc("#cdd6e0")
		switch {
		case strings.HasPrefix(line, "$ "):
			col = hexc("#6ee7b7")
		case isSeparator(line):
			col = hexc("#7c8797")
		}
		text(img, 16, y, line, col)
		y += 18
		if y > imgH-10 {
			break
		}
	}
	return img
}

func isSeparator(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, "---") || strings.HasPrefix(t, "===") || strings.HasPrefix(t, "Key ") || strings.HasPrefix(t, "Path ")
}

// ---- Web console screens ----

var (
	uiBg     = hexc("#0f1216")
	uiPanel  = hexc("#171b21")
	uiPanel2 = hexc("#1e242c")
	uiBorder = hexc("#2a323c")
	uiText   = hexc("#e6eaef")
	uiMuted  = hexc("#8b97a7")
	uiAccent = hexc("#4c9aff")
	uiGreen  = hexc("#6ee7b7")
)

func uiLogin(iconDir string) *image.RGBA {
	img := canvas(uiBg)
	// centered card
	cx0, cy0, cx1, cy1 := 260, 70, 640, 500
	fillRect(img, cx0, cy0, cx1, cy1, uiPanel)
	border(img, cx0, cy0, cx1, cy1, uiBorder)
	drawIcon(img, iconDir, "128x128.png", 386, 96)
	textCenter(img, cx0, cx1, 240, "keephippo", uiText)
	textCenter(img, cx0, cx1, 262, "A Vault-compatible secrets manager", uiMuted)
	// tabs
	tabW := 110
	labels := []string{"Token", "Userpass", "AppRole"}
	for i, l := range labels {
		x0 := cx0 + 20 + i*(tabW+6)
		c := uiPanel2
		fg := uiMuted
		if i == 0 {
			c = uiAccent
			fg = hexc("#06121f")
		}
		fillRect(img, x0, 290, x0+tabW, 316, c)
		textCenter(img, x0, x0+tabW, 307, l, fg)
	}
	inputBox(img, cx0+20, 330, cx1-20, 360, "Token", uiMuted)
	fillRect(img, cx0+20, 380, cx1-20, 412, uiAccent)
	textCenter(img, cx0+20, cx1-20, 401, "Sign in", hexc("#06121f"))
	textCenter(img, cx0, cx1, 470, "version v0.2.0", uiMuted)
	return img
}

func uiSecrets() *image.RGBA {
	img, mainX := shell("Secrets")
	// mounts card
	card(img, mainX, 70, 876, 210, "Secrets engines")
	tableHeader(img, mainX+16, 108, []string{"Path", "Type", "Version"}, []int{0, 220, 400})
	rows := [][]string{{"secret/", "kv", ""}, {"transit/", "transit", ""}, {"kv2/", "kv", "2"}}
	for i, r := range rows {
		y := 132 + i*24
		for j, cell := range r {
			text(img, mainX+16+[]int{0, 220, 400}[j], y, cell, uiText)
		}
	}
	// read/write card
	card(img, mainX, 300, 876, 500, "Read / write a secret")
	inputBox(img, mainX+16, 340, 500, 370, "secret/myapp/db", uiText)
	fillRect(img, mainX+16, 386, 90, 414, uiAccent)
	textCenter(img, mainX+16, 90, 405, "Read", hexc("#06121f"))
	fillRect(img, mainX+100, 386, 180, 414, uiPanel2)
	textCenter(img, mainX+100, 180, 405, "Write", uiText)
	text(img, mainX+16, 452, "password  s3cr3t", uiGreen)
	text(img, mainX+16, 472, "username  admin", uiGreen)
	return img
}

func uiPolicies() *image.RGBA {
	img, mainX := shell("Policies")
	card(img, mainX, 70, 876, 500, "Policies (ACL)")
	inputBox(img, mainX+16, 110, 260, 140, "app", uiText)
	fillRect(img, mainX+276, 110, 340, 140, uiAccent)
	textCenter(img, mainX+276, 340, 131, "Load", hexc("#06121f"))
	// editor
	fillRect(img, mainX+16, 160, 860, 460, hexc("#0b0e12"))
	border(img, mainX+16, 160, 860, 460, uiBorder)
	lines := []string{
		`path "secret/data/myapp/*" {`,
		`  capabilities = ["read", "list"]`,
		`}`,
	}
	for i, l := range lines {
		text(img, mainX+28, 186+i*20, l, uiText)
	}
	fillRect(img, mainX+16, 476, 90, 504, uiAccent)
	textCenter(img, mainX+16, 90, 495, "Save", hexc("#06121f"))
	return img
}

func uiConsole() *image.RGBA {
	img, mainX := shell("Console")
	card(img, mainX, 70, 876, 500, "Interactive console")
	lines := []struct {
		s   string
		col color.RGBA
	}{
		{"> write secret/x a=b", uiGreen},
		{`{ "request_id": "…", "data": null }`, uiText},
		{"> read secret/x", uiGreen},
		{`{`, uiText},
		{`  "data": { "a": "b" },`, uiText},
		{`  "lease_duration": 0, "renewable": false`, uiText},
		{`}`, uiText},
	}
	for i, l := range lines {
		text(img, mainX+20, 120+i*22, l.s, l.col)
	}
	inputBox(img, mainX+16, 470, 860, 500, "> write secret/x a=b", uiMuted)
	return img
}

func uiAbout(iconDir string) *image.RGBA {
	img, mainX := shell("About")
	card(img, mainX, 70, 876, 320, "")
	drawIcon(img, iconDir, "256x256.png", mainX+40, 110)
	text(img, mainX+320, 150, "keephippo", uiText)
	text(img, mainX+320, 186, "A from-scratch, Vault-compatible secrets manager.", uiMuted)
	text(img, mainX+320, 214, "Version: v0.2.0", uiText)
	text(img, mainX+320, 246, "The web console is just another client of the /v1/* API.", uiMuted)
	return img
}

// shell draws the app top bar + sidebar and returns the image and the left x of
// the main content area.
func shell(active string) (*image.RGBA, int) {
	img := canvas(uiBg)
	// top bar
	fillRect(img, 0, 0, imgW, 44, uiPanel)
	border(img, 0, 0, imgW, 44, uiBorder)
	text(img, 16, 27, "keephippo", uiText)
	fillRect(img, imgW-180, 12, imgW-96, 32, hexc("#123023"))
	textCenter(img, imgW-180, imgW-96, 27, "unsealed", uiGreen)
	fillRect(img, imgW-88, 12, imgW-16, 32, uiPanel2)
	textCenter(img, imgW-88, imgW-16, 27, "Sign out", uiText)
	// sidebar
	fillRect(img, 0, 44, 170, imgH, uiPanel)
	border(img, 0, 44, 170, imgH, uiBorder)
	navs := []string{"Secrets", "Policies", "Tokens", "Leases", "Audit", "Console", "About"}
	for i, n := range navs {
		y0 := 58 + i*36
		if n == active {
			fillRect(img, 8, y0, 162, y0+30, uiPanel2)
		}
		col := uiMuted
		if n == active {
			col = uiText
		}
		text(img, 20, y0+20, n, col)
	}
	return img, 190
}

// ---- drawing helpers ----

func canvas(bg color.RGBA) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, imgW, imgH))
	draw.Draw(img, img.Bounds(), &image.Uniform{bg}, image.Point{}, draw.Src)
	return img
}

func fillRect(img *image.RGBA, x0, y0, x1, y1 int, c color.RGBA) {
	draw.Draw(img, image.Rect(x0, y0, x1, y1), &image.Uniform{c}, image.Point{}, draw.Src)
}

func border(img *image.RGBA, x0, y0, x1, y1 int, c color.RGBA) {
	fillRect(img, x0, y0, x1, y0+1, c)
	fillRect(img, x0, y1-1, x1, y1, c)
	fillRect(img, x0, y0, x0+1, y1, c)
	fillRect(img, x1-1, y0, x1, y1, c)
}

func card(img *image.RGBA, x0, y0, x1, y1 int, title string) {
	fillRect(img, x0, y0, x1, y1, uiPanel)
	border(img, x0, y0, x1, y1, uiBorder)
	if title != "" {
		text(img, x0+16, y0+26, title, uiText)
	}
}

func inputBox(img *image.RGBA, x0, y0, x1, y1 int, placeholder string, fg color.RGBA) {
	fillRect(img, x0, y0, x1, y1, uiPanel2)
	border(img, x0, y0, x1, y1, uiBorder)
	text(img, x0+10, (y0+y1)/2+5, placeholder, fg)
}

func tableHeader(img *image.RGBA, x, y int, cols []string, offs []int) {
	for i, c := range cols {
		text(img, x+offs[i], y, c, uiMuted)
	}
}

func text(img *image.RGBA, x, y int, s string, c color.RGBA) {
	d := &font.Drawer{
		Dst:  img,
		Src:  &image.Uniform{c},
		Face: basicfont.Face7x13,
		Dot:  fixed.P(x, y),
	}
	d.DrawString(s)
}

func textCenter(img *image.RGBA, x0, x1, y int, s string, c color.RGBA) {
	w := len(s) * 7 // basicfont advance is 7px
	x := x0 + (x1-x0-w)/2
	if x < x0 {
		x = x0
	}
	text(img, x, y, s, c)
}

func drawIcon(img *image.RGBA, iconDir, name string, x, y int) {
	f, err := os.Open(filepath.Join(iconDir, name))
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	ic, err := png.Decode(f)
	if err != nil {
		return
	}
	b := ic.Bounds()
	draw.Draw(img, image.Rect(x, y, x+b.Dx(), y+b.Dy()), ic, b.Min, draw.Over)
}

func save(dir, name string, img image.Image) {
	p := filepath.Join(dir, name+".png")
	f, err := os.Create(p)
	if err != nil {
		fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := png.Encode(f, img); err != nil {
		fatal(err)
	}
}

func hexc(s string) color.RGBA {
	s = strings.TrimPrefix(s, "#")
	var r, g, b uint8
	_, _ = fmt.Sscanf(s, "%02x%02x%02x", &r, &g, &b)
	return color.RGBA{r, g, b, 255}
}

func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	// Walk up until we find go.mod's parent that also has a docs/ sibling.
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "docs")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "src")); err == nil {
				return dir, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("could not locate repo root from %s", wd)
		}
		dir = parent
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "docsgen:", err)
	os.Exit(1)
}
