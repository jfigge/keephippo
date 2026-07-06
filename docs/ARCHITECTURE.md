# Architecture

keephippo mirrors Vault's layering. Each layer depends only on the one below, so
the phases build bottom-up.

```
        ┌─────────────────────────────────────────────┐
        │  CLI (cmd/keephippo) ─────► Go API client     │  console app + SDK
        └───────────────┬─────────────────────────────┘
                        │ HTTP /v1/*  (X-Vault-Token)
        ┌───────────────▼─────────────────────────────┐
        │  HTTP layer (internal/http)                   │  routing, envelope, sys/*
        ├───────────────────────────────────────────────┤
        │  Core (internal/core)                         │  router + auth check
        │   • mount tables (secret + auth)              │
        │   • policy store (ACL eval)                   │
        │   • token store (create/lookup/revoke)        │
        │   • expiration manager (leases)               │
        │   • seal manager (sealed/unsealed state)      │
        ├───────────────────────────────────────────────┤
        │  Logical backends (builtin/*)                 │  engines + auth methods
        │   via logical.Backend interface               │
        ├───────────────────────────────────────────────┤
        │  Barrier (internal/barrier)                   │  AES-256-GCM; encrypts all
        ├───────────────────────────────────────────────┤
        │  Physical storage (internal/physical)         │  inmem / file(bbolt) / raft
        └───────────────────────────────────────────────┘
```

## Invariants

- **Nothing hits physical storage unencrypted.** The barrier sits between core
  and physical; the barrier key is encrypted by the root key, which the seal
  (Shamir shares or an auto-unseal KMS) protects.
- **Sealed by default.** On boot the server is sealed and serves almost nothing
  except `sys/health`, `sys/seal-status`, and `sys/unseal`. Unsealing
  reconstructs the root key → decrypts the barrier key → mounts backends.
- **Everything is a path.** A request is `(operation, path, data, token)`; core
  routes by longest-prefix match against the mount table, after ACL evaluation.
- **Leases/TTLs are first-class.** Dynamic secrets and tokens carry leases
  tracked by the expiration manager, which revokes on expiry and supports
  renew/revoke.

See [`../features/`](../features/) for the per-phase build plan.
