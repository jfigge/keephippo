# keephippo

> A from-scratch, **Vault-compatible** secrets manager — server + console app (CLI).

[![CI](https://github.com/jfigge/keephippo/actions/workflows/ci.yml/badge.svg)](https://github.com/jfigge/keephippo/actions/workflows/ci.yml)
[![CodeQL](https://github.com/jfigge/keephippo/actions/workflows/codeql.yml/badge.svg)](https://github.com/jfigge/keephippo/actions/workflows/codeql.yml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-brightgreen.svg)](LICENSE)
![Platforms](https://img.shields.io/badge/platforms-macOS%20%C2%B7%20Linux%20%C2%B7%20Windows-blue)
[![Release](https://img.shields.io/github/v/release/jfigge/keephippo?include_prereleases&sort=semver)](https://github.com/jfigge/keephippo/releases)

keephippo replicates HashiCorp Vault's **HTTP API** and core features (secrets
engines, auth methods, policies, tokens, leases, seal/unseal) so existing Vault
clients keep working — while shipping its own console application and branding.

> ⚠️ **Not audited. Use at your own risk.** keephippo is an educational /
> portfolio implementation of a secrets manager. It has **not** undergone a
> security audit. Do not use it to protect real secrets until a release says
> otherwise. See [SECURITY.md](SECURITY.md).

## Status

Built in phases. See [`features/`](features/) for the per-phase build prompts and
their definitions of done.

| Phase | Scope | State |
|------:|-------|-------|
| 0 | Scaffolding · Makefile · CI · `keephippo` binary | ✅ done |
| 1 | Storage · barrier · Shamir seal/unseal | ✅ done |
| 2 | Mounts · HTTP core · KV v1 · token auth | ✅ done |
| 3 | Policies (ACL) · login · token lifecycle | ⬜ next |
| 4 | Full CLI to Vault parity | ⬜ |
| 5–7 | userpass/approle · KV v2 · leases/transit · audit/wrapping | ⬜ |
| 8–9 | Raft HA · auto-unseal · identity · Web UI | ⬜ |

## Quick start

```console
# Build from source (Go 1.26+)
make build
./build/keephippo info

# Dev server (in-memory, auto-unseal) — available from Phase 1
make dev
```

keephippo keeps Vault **wire compatibility**: the `/v1/` path model, the
`X-Vault-Token` header, default port `8200`, the `VAULT_ADDR` / `VAULT_TOKEN`
environment variables (it also accepts `KEEPHIPPO_ADDR` / `KEEPHIPPO_TOKEN`), and
the standard JSON response envelope — so `vault status -address=…` against a
keephippo server works.

## Development

```console
make install     # dev tools (gofumpt, golangci-lint, govulncheck, goreleaser)
make             # clean → fmt → lint → test → build
make help        # list all targets
```

## Non-goals

To keep scope sane, keephippo explicitly does **not** aim to provide:

- Vault **Enterprise** features: replication, HSM integration, namespaces, Sentinel.
- The full catalogue of engines/auth methods — a curated, useful subset only.
- Drop-in migration of a real Vault's on-disk storage format.

## Compatibility & trademarks

"Vault" and "HashiCorp" are trademarks of their respective owners. keephippo is
independent and **not** affiliated with or endorsed by HashiCorp/IBM. It is a
clean-room implementation against the public API spec, using the MPL-2.0
[OpenBao](https://openbao.org) project as its reference where needed — never
Vault's BUSL-licensed source. "Vault-compatible" is a factual description only.

## License & contributing

Licensed under the **Mozilla Public License 2.0** — see [LICENSE](LICENSE) and
[NOTICE](NOTICE). Contributions require a **Developer Certificate of Origin**
sign-off (`git commit -s`); see [CONTRIBUTING.md](CONTRIBUTING.md) and [DCO](DCO).
