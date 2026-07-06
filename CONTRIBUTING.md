# Contributing to keephippo

Thanks for your interest! keephippo is a secrets manager, so correctness and
provenance matter more than usual — please read this before opening a PR.

## Developer Certificate of Origin (DCO)

Every commit must be signed off, certifying you wrote the code or have the right
to contribute it under the project license (see [DCO](DCO)):

```console
git commit -s -m "your message"
```

This appends a `Signed-off-by: Your Name <you@example.com>` trailer. We use the
DCO, **not** a CLA. PRs with unsigned commits will be asked to amend.

## Licensing & clean-room policy

- keephippo is **MPL-2.0** (see [LICENSE](LICENSE)). New Go files should carry
  the SPDX header below.
- **Do not** copy, paste, port, or paraphrase code from HashiCorp Vault
  **≥ 1.15** (BUSL-1.1). Implement against the public HTTP API spec.
- Where a reference is needed, use only **MPL-2.0** sources — primarily
  [OpenBao](https://openbao.org). Any file adapted from an MPL-2.0 work keeps its
  original header and is recorded in [NOTICE](NOTICE).

```go
// Copyright (c) the keephippo authors
// SPDX-License-Identifier: MPL-2.0
```

## Development workflow

```console
make install   # dev tools: gofumpt, golangci-lint, govulncheck, goreleaser
make           # clean → fmt → lint → test → build (must pass before you push)
make help      # list all targets
```

- Format with `make fmt` (gofumpt).
- Keep `make lint`, `make test` (race), and `make vuln` green.
- Add tests with your change; secrets-handling code needs unit **and** e2e
  coverage.

## Branch & release model

- Work on feature branches; open PRs against `main`.
- `release` is a strict fast-forward of `main`. Releases are cut with
  `make release VERSION=x.y.z` (maintainers only).

## Reporting security issues

Do **not** open a public issue for vulnerabilities — see [SECURITY.md](SECURITY.md).
