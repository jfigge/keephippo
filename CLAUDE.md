# CLAUDE.md

Guidance for Claude Code (and other agents) working in this repository.

## What this is

**keephippo** — a from-scratch, **Vault-compatible** secrets manager: an HTTP
server plus a console application (CLI). It replicates HashiCorp Vault's HTTP API
and core features (secrets engines, auth methods, policies, tokens, leases,
seal/unseal) so existing Vault clients keep working, while shipping its own
console app and branding. It also embeds a web console at `/ui`.

> ⚠️ Educational / portfolio project. **Not security-audited.** Correctness and
> provenance matter more than usual here — this is a secrets manager.

## Layout

The Go module is rooted at **`src/`** (`module github.com/jfigge/keephippo`,
Go 1.26). Run Go commands from `src/`, but prefer the Makefile targets at the
repo root.

- `src/cmd/keephippo` — main binary entrypoint; `src/cmd/docsgen` — docs generator
- `src/internal/` — server internals: `core`, `http`, `physical` (storage),
  `barrier`, `seal`, `policy`, `logical`, `audit`, `command` (CLI), `version`
- `src/builtin/` — pluggable engines: `logical/{kv,transit,totp,cubbyhole}`,
  `credential/{userpass,approle,cert}`
- `src/api/` — Go API client · `src/web/` — embedded web console (static HTML/CSS/JS)
- `src/e2e/` — integration suite · `src/testdata/` — fixtures & dev certs
- `docs/`, `website/`, `features/` — user guide, marketing site, per-phase build prompts

## Commands (run from repo root)

```console
make            # full pipeline: clean → fmt → lint → test → ui → build
make build      # build ./build/keephippo for the host
make dev        # run a dev server (in-mem storage, auto-unseal); prints root token + unseal key
make test       # unit tests with the race detector + coverage
make e2e        # integration suite
make lint       # golangci-lint
make fmt        # format (gofumpt)
make vuln       # govulncheck
make help       # list every target
```

Keep `make lint`, `make test` (race), and `make vuln` green before pushing.
Secrets-handling code needs **unit and e2e** coverage.

## Conventions

- **License MPL-2.0.** New Go files carry the SPDX header:
  ```go
  // Copyright (c) the keephippo authors
  // SPDX-License-Identifier: MPL-2.0
  ```
- **Clean-room.** Do **not** copy/paste/port/paraphrase code from HashiCorp Vault
  ≥ 1.15 (BUSL-1.1). Implement against the public HTTP API spec. Where a reference
  is needed, use only MPL-2.0 sources — primarily [OpenBao](https://openbao.org) —
  and record any adapted file in `NOTICE`.
- **Wire compatibility** with Vault: `/v1/` paths, `X-Vault-Token` header, port
  `8200`, `VAULT_ADDR`/`VAULT_TOKEN` env (also `KEEPHIPPO_ADDR`/`KEEPHIPPO_TOKEN`),
  standard JSON response envelope. Don't break these.
- Work on feature branches; open PRs against `main`.

## Git & committing

**Do not commit automatically.** Make and stage changes, run the checks, and
report what changed — then let the maintainer review and commit. Only run
`git commit` when the user explicitly asks you to in that message.
(`git commit` is also denied by `.claude/settings.json`.)

When a commit *is* requested, every commit must be **DCO signed off**
(`git commit -s`) — see [CONTRIBUTING.md](CONTRIBUTING.md) and [DCO](DCO).

## Releases

**There are no pre-releases.** Two kinds of change exist:

- **Commits** — the normal path. They update the code and land on `main` (via a
  feature branch + PR) *without* cutting a release. This is what almost every
  change is.
- **Releases** — a deliberate, maintainer-only step that ships a version and
  publishes it to the website. Cut with `make release VERSION=x.y.z`; `release`
  is a strict fast-forward of `main`.

So: commit freely to advance the code, but do **not** treat "done" as "released."
A release is a separate, explicit action that goes to the site — never
auto-release, and never cut a pre-release / release candidate.
