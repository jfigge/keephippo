# User-guide images

Every image here is exactly **900 × 562 px** PNG and is **generated** — not a raw
screen capture — by the pure-Go tool `src/cmd/docsgen`. Regenerate the whole set
after a CLI-output or web-console change with:

```sh
make docs-images
```

The generator has no browser or system dependency: CLI shots are rendered from
real captured command output; web-console shots are styled panels that mirror
`src/web/app.css` and embed the real badge from `src/web/icons/`.

| Image | Produced from |
|-------|---------------|
| `cli-status.png` | `keephippo status` |
| `cli-secrets-list.png` | `keephippo secrets list` |
| `cli-kv-put.png` | `keephippo kv put secret/myapp/db username=admin password=s3cr3t` |
| `cli-kv-get.png` | `keephippo kv get secret/myapp/db` |
| `cli-token-create.png` | `keephippo token create -policy=default -ttl=1h` |
| `cli-transit.png` | `keephippo transit encrypt/decrypt app …` |
| `cli-read-json.png` | `keephippo read secret/myapp/db -format=json` |
| `cli-unwrap.png` | `keephippo -wrap-ttl=120s read …` then `keephippo unwrap …` |
| `ui-login.png` | Web console — login screen |
| `ui-secrets.png` | Web console — Secrets screen |
| `ui-policies.png` | Web console — Policies screen |
| `ui-console.png` | Web console — interactive console (REPL) |
| `ui-about.png` | Web console — About panel |

The captured CLI text is embedded in `src/cmd/docsgen/main.go`; update it there
(volatile values like tokens/timestamps are normalized for readability) when the
output format changes.
