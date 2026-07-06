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
| `sys/mounts` | ✅ | 2 | list/enable/disable secret engines |
| `sys/remount` | ✅ | 2 | move a mount, data preserved |
| `sys/auth` | 🚧 | 4 | list/enable/disable wired; method backends in Phase 5 |
| `sys/mounts/<p>/tune` | ✅ | 4 | tune mount config |
| `sys/policies/acl` | ✅ | 3 | CRUD ACL policies (+ legacy `sys/policy`) |
| `sys/capabilities-self` | ✅ | 3 | + `sys/capabilities` |
| `sys/leases/*` | ⬜ | 6 | lookup/renew/revoke/revoke-prefix |
| `sys/audit` | 🚧 | 4/7 | list wired (empty); devices in Phase 7 |
| `sys/wrapping/*` | ⬜ | 7 | wrap/unwrap/lookup/rewrap |

## Auth methods (`auth/`)

| Method | Status | Phase | Notes |
|--------|:------:|:-----:|-------|
| `token` | ✅ | 3 | create/lookup(-self)/renew/revoke, accessors, TTL, num_uses |
| `userpass` | ⬜ | 5 | |
| `approle` | ⬜ | 5 | |

## Secrets engines

| Engine | Status | Phase | Notes |
|--------|:------:|:-----:|-------|
| `kv` v1 | ✅ | 2 | unversioned put/get/list/delete |
| `kv` v2 | ⬜ | 5 | versioned |
| `transit` | ⬜ | 6 | encryption as a service |
| `cubbyhole` | ⬜ | 7 | per-token store |

## Wire conventions

| Item | Status | Notes |
|------|:------:|-------|
| `/v1/` path prefix | ✅ | |
| `X-Vault-Token` header | ✅ | authenticated + ACL-authorized on every request |
| Standard JSON envelope | ✅ | logical + `auth` block; golden-file tested |
| Status codes | 🚧 | 200/204/400/403/404/501/503 wired; 429 later |
