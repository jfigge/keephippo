# App icons

The keephippo application icon set, in the same size lineup RestHippo ships
(the electron-builder app-icon set):

| File            | Typical use                                              |
| --------------- | -------------------------------------------------------- |
| `16x16.png`     | browser favicon (small), tray                            |
| `24x24.png`     | favicon / small UI chrome                                 |
| `32x32.png`     | browser favicon (standard), Windows small tile           |
| `48x48.png`     | Linux hicolor, Windows                                    |
| `64x64.png`     | favicon (hi-DPI), UI logo                                 |
| `71x71.png`     | Windows small tile                                        |
| `128x128.png`   | login screen / About-dialog badge                        |
| `150x150.png`   | Windows medium tile                                       |
| `256x256.png`   | About dialog, `.ico` source, macOS                       |
| `300x300.png`   | Windows large tile                                        |
| `512x512.png`   | landing website hero / PWA icon                           |
| `1024x1024.png` | macOS `.icns` source, store artwork, print               |

Each icon is a transparent-cornered RGBA PNG: the rounded-square hippo-safe
badge floats on transparency (the master's flat corner backdrop is knocked out),
so the icons composite cleanly over any background.

## Consumers

- **Server / web UI** (Phase 09) — embedded via `go:embed` and served under
  `/ui`; favicon and the login / About-screen badge come from this set.
- **Landing website** (master §11, Cloudflare Pages) — favicon and hero art.
- **Packaging** (master §11, GoReleaser) — desktop/store icons derive from the
  larger sizes.

## Regenerating

These are generated from the design master `icons/keephippo.png` (repo root).
To rebuild the whole set after the master changes:

```sh
go run scripts/make-icons.go
```

The generator (`scripts/make-icons.go`, stdlib-only) flood-fills the master's
flat corner backdrop to transparency (whatever colour it is — it's sampled from
a corner, not assumed) and area-downsamples to every size in premultiplied-alpha
space so the rounded edges stay fringe-free. Do not hand-edit these PNGs —
change the master and regenerate.

If the master itself ever loses its transparency (e.g. it gets re-saved with a
flat white/black backdrop), heal it in place with:

```sh
go run scripts/make-icons.go -heal-master
```

The committed `icons/keephippo.png` master is already a transparent-cornered
RGBA PNG.
