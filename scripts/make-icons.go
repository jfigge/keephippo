//go:build ignore

// make-icons.go regenerates the keephippo app-icon set from the design master.
//
// It reads the master art at icons/keephippo.png (a rounded-square badge on a
// flat backdrop), knocks that backdrop out of the corners to transparency, and
// emits the full size set as transparent-cornered RGBA PNGs into src/web/icons/
// — the embed root the server / web UI (Phase 09) and the landing website read
// from. The backdrop may be any flat colour (black, white, …); it is detected
// from a corner rather than assumed.
//
// The size set mirrors the RestHippo electron-builder app-icon set:
//
//	16 24 32 48 64 71 128 150 256 300 512 1024
//
// Usage (from the repo root; stdlib-only, so no module or extra deps needed):
//
//	go run scripts/make-icons.go                       # regenerate the icon set
//	go run scripts/make-icons.go <master.png> <outdir> # from an explicit master/dir
//	go run scripts/make-icons.go -heal-master          # rewrite the master itself
//	                                                   # with transparent corners
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
)

var sizes = []int{16, 24, 32, 48, 64, 71, 128, 150, 256, 300, 512, 1024}

func main() {
	args := os.Args[1:]
	heal := false
	if len(args) > 0 && args[0] == "-heal-master" {
		heal, args = true, args[1:]
	}

	src := "icons/keephippo.png"
	out := "src/web/icons"
	switch {
	case heal && len(args) == 1:
		src = args[0]
	case heal && len(args) == 0:
	case !heal && len(args) == 2:
		src, out = args[0], args[1]
	case !heal && len(args) == 0:
	default:
		fmt.Fprintln(os.Stderr, "usage:\n"+
			"  go run scripts/make-icons.go [<master.png> <outdir>]     # generate the icon set\n"+
			"  go run scripts/make-icons.go -heal-master [<master.png>] # rewrite the master with transparent corners")
		os.Exit(2)
	}

	master := loadRGBA(src)
	cleared := clearCorners(master)
	total := master.Rect.Dx() * master.Rect.Dy()
	fmt.Printf("corners: cleared %d/%d px (%.1f%%) to transparent\n",
		cleared, total, 100*float64(cleared)/float64(total))

	if heal {
		writePNG(src, master)
		fmt.Printf("healed master %s → transparent-cornered RGBA\n", src)
		return
	}

	if err := os.MkdirAll(out, 0o755); err != nil {
		fatal(err)
	}
	for _, s := range sizes {
		dst := resizeArea(master, s, s)
		name := filepath.Join(out, fmt.Sprintf("%dx%d.png", s, s))
		writePNG(name, dst)
		fmt.Printf("wrote %s\n", name)
	}
}

func loadRGBA(path string) *image.RGBA {
	f, err := os.Open(path)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		fatal(err)
	}
	b := img.Bounds()
	rgba := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	for y := 0; y < b.Dy(); y++ {
		for x := 0; x < b.Dx(); x++ {
			rgba.Set(x, y, img.At(b.Min.X+x, b.Min.Y+y))
		}
	}
	return rgba
}

// clearCorners knocks the master's flat corner backdrop out to transparency and
// reports how many pixels it cleared. It samples the backdrop from a corner,
// then flood-fills (4-connected BFS from all four corners) every pixel that
// matches it — either near-transparent (if the master is already RGBA) or within
// a small RGB distance of the corner colour (a flat black/white/coloured
// backdrop). Because the flood is connectivity-based it stops at the badge edge
// and never reaches same-coloured interior details (they are enclosed by the
// badge), so it is safe regardless of the backdrop the master ships with.
func clearCorners(img *image.RGBA) int {
	w := img.Rect.Dx()
	h := img.Rect.Dy()
	bg := img.RGBAAt(0, 0)  // backdrop reference sampled from a corner
	transparent := bg.A < 8 // master already carries an alpha backdrop
	const tol2 = 70 * 70    // squared per-pixel RGB distance from the backdrop

	isBackdrop := func(c color.RGBA) bool {
		if transparent {
			return c.A < 8
		}
		dr := int(c.R) - int(bg.R)
		dg := int(c.G) - int(bg.G)
		db := int(c.B) - int(bg.B)
		return c.A >= 8 && dr*dr+dg*dg+db*db <= tol2
	}

	visited := make([]bool, w*h)
	stack := make([][2]int, 0, 1024)
	push := func(x, y int) {
		if x < 0 || y < 0 || x >= w || y >= h || visited[y*w+x] {
			return
		}
		if !isBackdrop(img.RGBAAt(x, y)) {
			return
		}
		visited[y*w+x] = true
		stack = append(stack, [2]int{x, y})
	}
	push(0, 0)
	push(w-1, 0)
	push(0, h-1)
	push(w-1, h-1)
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		push(p[0]+1, p[1])
		push(p[0]-1, p[1])
		push(p[0], p[1]+1)
		push(p[0], p[1]-1)
	}
	cleared := 0
	for i, on := range visited {
		if on {
			img.SetRGBA(i%w, i/w, color.RGBA{})
			cleared++
		}
	}
	return cleared
}

// resizeArea downscales with an analytic area (box) filter in premultiplied
// space, so transparent-corner edges resample without a dark fringe.
func resizeArea(src *image.RGBA, dw, dh int) *image.RGBA {
	sw := src.Rect.Dx()
	sh := src.Rect.Dy()
	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	scaleX := float64(sw) / float64(dw)
	scaleY := float64(sh) / float64(dh)

	for dy := 0; dy < dh; dy++ {
		y0 := float64(dy) * scaleY
		y1 := float64(dy+1) * scaleY
		for dx := 0; dx < dw; dx++ {
			x0 := float64(dx) * scaleX
			x1 := float64(dx+1) * scaleX

			var sumW, sA, sR, sG, sB float64
			for py := int(math.Floor(y0)); py < int(math.Ceil(y1)); py++ {
				wy := overlap(y0, y1, float64(py), float64(py+1))
				if wy <= 0 {
					continue
				}
				for px := int(math.Floor(x0)); px < int(math.Ceil(x1)); px++ {
					wx := overlap(x0, x1, float64(px), float64(px+1))
					if wx <= 0 {
						continue
					}
					w := wx * wy
					c := src.RGBAAt(px, py)
					a := float64(c.A) / 255
					sumW += w
					sA += w * a
					sR += w * a * float64(c.R)
					sG += w * a * float64(c.G)
					sB += w * a * float64(c.B)
				}
			}
			if sumW == 0 {
				continue
			}
			a := sA / sumW
			var out color.RGBA
			out.A = clamp8(a * 255)
			if a > 0 {
				out.R = clamp8((sR / sumW) / a)
				out.G = clamp8((sG / sumW) / a)
				out.B = clamp8((sB / sumW) / a)
			}
			dst.SetRGBA(dx, dy, out)
		}
	}
	return dst
}

func overlap(a0, a1, b0, b1 float64) float64 {
	lo := math.Max(a0, b0)
	hi := math.Min(a1, b1)
	if hi <= lo {
		return 0
	}
	return hi - lo
}

func clamp8(v float64) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v + 0.5)
}

func writePNG(path string, img image.Image) {
	f, err := os.Create(path)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "make-icons:", err)
	os.Exit(1)
}
