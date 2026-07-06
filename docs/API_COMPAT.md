# API compatibility scoreboard

A living matrix of Vault-compatible endpoints keephippo implements. Status:
✅ done · 🚧 in progress · ⬜ planned.

## System backend (`sys/`)

| Endpoint | Status | Phase | Notes |
|----------|:------:|:-----:|-------|
| `sys/health` | ✅ | 1 | 200/503/501 status codes |
| `sys/seal-status` | ✅ | 1 | |
| `sys/init` | ✅ | 1 | Shamir shares + root token |
| `sys/unseal` | ✅ | 1 | supports `reset` |
| `sys/seal` | ✅ | 1 | auth enforced from Phase 3 |
| `sys/mounts` | ⬜ | 2 | list/enable/disable secret engines |
| `sys/remount` | ⬜ | 2 | |
| `sys/auth` | ⬜ | 5 | list/enable/disable auth methods |
| `sys/policies/acl` | ⬜ | 3 | CRUD ACL policies |
| `sys/capabilities-self` | ⬜ | 3 | |
| `sys/leases/*` | ⬜ | 6 | lookup/renew/revoke/revoke-prefix |
| `sys/audit` | ⬜ | 7 | list/enable/disable audit devices |
| `sys/wrapping/*` | ⬜ | 7 | wrap/unwrap/lookup/rewrap |

## Auth methods (`auth/`)

| Method | Status | Phase | Notes |
|--------|:------:|:-----:|-------|
| `token` | ⬜ | 2–3 | built-in |
| `userpass` | ⬜ | 5 | |
| `approle` | ⬜ | 5 | |

## Secrets engines

| Engine | Status | Phase | Notes |
|--------|:------:|:-----:|-------|
| `kv` v1 | ⬜ | 2 | |
| `kv` v2 | ⬜ | 5 | versioned |
| `transit` | ⬜ | 6 | encryption as a service |
| `cubbyhole` | ⬜ | 7 | per-token store |

## Wire conventions

| Item | Status | Notes |
|------|:------:|-------|
| `/v1/` path prefix | ✅ | |
| `X-Vault-Token` header | 🚧 | sent by client; enforced from Phase 3 |
| Standard JSON envelope | ⬜ | logical endpoints, Phase 2 |
| Status codes | 🚧 | 200/204/400/404/501/503 wired; 403/429 later |
