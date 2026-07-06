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
| `sys/auth` | ✅ | 4/5 | list/enable/disable; userpass + approle backends in Phase 5 |
| `sys/mounts/<p>/tune` | ✅ | 4 | tune mount config |
| `sys/internal/ui/mounts` | ✅ | 5 | mount-version preflight for the `kv` CLI |
| `sys/policies/acl` | ✅ | 3 | CRUD ACL policies (+ legacy `sys/policy`) |
| `sys/capabilities-self` | ✅ | 3 | + `sys/capabilities` |
| `sys/leases/*` | ✅ | 6 | lookup/renew/revoke/revoke-prefix/revoke-force; background auto-revoke |
| `sys/audit` | ✅ | 7 | file + syslog devices; HMAC-obscured; fail-closed |
| `sys/audit-hash/<p>` | ✅ | 7 | HMAC of a given input |
| `sys/wrapping/*` | ✅ | 7 | wrap/unwrap/lookup/rewrap; single-use; `X-Vault-Wrap-TTL` |

## Auth methods (`auth/`)

| Method | Status | Phase | Notes |
|--------|:------:|:-----:|-------|
| `token` | ✅ | 3 | create/lookup(-self)/renew/revoke, accessors, TTL, num_uses |
| `userpass` | ✅ | 5 | users CRUD (bcrypt), login → policy-scoped token |
| `approle` | ✅ | 5 | role/role-id/secret-id, constant-time login, secret_id TTL/num-uses |
| `cert` | ✅ | 8 | TLS client-certificate login (matches a trusted cert or CA) |

## Secrets engines

| Engine | Status | Phase | Notes |
|--------|:------:|:-----:|-------|
| `kv` v1 | ✅ | 2 | unversioned put/get/list/delete |
| `kv` v2 | ✅ | 5 | versioning, data/metadata, delete/undelete/destroy, CAS, max_versions |
| `transit` | ✅ | 6 | encrypt/decrypt/rewrap, sign/verify, hmac, datakey; aes/chacha/ed25519/ecdsa; key rotation |
| `cubbyhole` | ✅ | 7 | per-token store; auto-mounted; destroyed on token revoke |
| `totp` | ✅ | 8 | RFC 6238 codes; key generate/import, code generate/validate |

## Identity & seal

| Feature | Status | Phase | Notes |
|---------|:------:|:-----:|-------|
| `identity/entity/*` | ✅ | 8 | entities + entity aliases mapping logins to a stable entity |
| `identity/group/*` | ✅ | 8 | groups; group policies apply to member entities' logins |
| Auto-unseal (`seal "transit"`) | ✅ | 8 | boots unsealed from a remote transit engine; no manual key entry |
| Integrated Storage (Raft HA) | ⬜ | 8 | not shipped (deferred) |
| Web console at `/ui` | ✅ | 9 | embedded static UI + interactive REPL; gated by `ui = true` |

## Wire conventions

| Item | Status | Notes |
|------|:------:|-------|
| `/v1/` path prefix | ✅ | |
| `X-Vault-Token` header | ✅ | authenticated + ACL-authorized on every request |
| Standard JSON envelope | ✅ | logical + `auth` block; golden-file tested |
| Status codes | 🚧 | 200/204/400/403/404/501/503 wired; 429 later |
