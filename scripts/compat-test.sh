#!/usr/bin/env bash
# Conformance harness: a golden envelope check that always runs offline, plus a
# live cross-check driving the real openbao/vault CLI against keephippo when one
# is installed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Golden envelope conformance (offline)"
go -C "$ROOT/src" test -tags=e2e -run 'TestEnvelopeGolden|TestKVLifecycleOverHTTP' ./e2e/...

# Find a Vault-compatible CLI.
CLI=""
for c in openbao bao vault; do
  if command -v "$c" >/dev/null 2>&1; then CLI="$c"; break; fi
done
if [[ -z "$CLI" ]]; then
  echo "==> No openbao/vault CLI found; skipping the live cross-check."
  echo "    Install one to enable it, e.g.:  brew install openbao"
  exit 0
fi

echo "==> Live cross-check: write with keephippo, read with '$CLI'"
BIN="$ROOT/build/keephippo"
go -C "$ROOT/src" build -o "$BIN" ./cmd/keephippo
"$BIN" server --dev >/tmp/keephippo-compat.log 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null' EXIT

ADDR="http://127.0.0.1:8200"
curl -s --retry 30 --retry-connrefused --retry-delay 1 "$ADDR/v1/sys/seal-status" >/dev/null
TOKEN=$(awk -F': ' '/Root Token/{print $2}' /tmp/keephippo-compat.log)
# Export both Vault- and OpenBao-style env vars so the CLI finds them either way.
export VAULT_ADDR="$ADDR" VAULT_TOKEN="$TOKEN" BAO_ADDR="$ADDR" BAO_TOKEN="$TOKEN"

"$BIN" secrets enable -path=secret kv >/dev/null
"$BIN" kv put secret/compat greeting=hello >/dev/null

echo "-- $CLI read secret/compat --"
"$CLI" read secret/compat

# --- KV v2: enable with keephippo, drive the full v2 lifecycle with the foreign CLI ---
echo "-- $CLI kv (v2) lifecycle against keephippo --"
"$BIN" secrets enable -version=2 -path=kv2 kv >/dev/null
"$CLI" kv put kv2/thing greeting=hello >/dev/null
"$CLI" kv put kv2/thing greeting=world >/dev/null
"$CLI" kv get kv2/thing
"$CLI" kv get -version=1 kv2/thing >/dev/null
"$CLI" kv metadata get kv2/thing >/dev/null
"$CLI" kv delete kv2/thing >/dev/null
"$CLI" kv undelete -versions=2 kv2/thing >/dev/null
"$CLI" kv destroy -versions=1 kv2/thing >/dev/null
echo "   KV v2 put/get/-version/metadata/delete/undelete/destroy OK"

# --- AppRole: enable with keephippo, log in with the foreign CLI ---
echo "-- $CLI AppRole login against keephippo --"
"$BIN" auth enable approle >/dev/null
"$CLI" write auth/approle/role/demo token_policies=default >/dev/null
ROLE_ID=$("$CLI" read -field=role_id auth/approle/role/demo/role-id)
SECRET_ID=$("$CLI" write -f -field=secret_id auth/approle/role/demo/secret-id)
"$CLI" write auth/approle/login role_id="$ROLE_ID" secret_id="$SECRET_ID" >/dev/null
echo "   AppRole role_id + secret_id login OK"

# --- transit: enable with keephippo, encrypt/decrypt/rotate/rewrap with the foreign CLI ---
echo "-- $CLI transit encrypt/decrypt against keephippo --"
"$BIN" secrets enable transit >/dev/null
"$CLI" write -f transit/keys/demo >/dev/null
PT=$(printf 'compat-secret' | base64)
CT=$("$CLI" write -field=ciphertext transit/encrypt/demo plaintext="$PT")
OUT=$("$CLI" write -field=plaintext transit/decrypt/demo ciphertext="$CT" | base64 --decode)
if [[ "$OUT" != "compat-secret" ]]; then echo "transit decrypt mismatch: $OUT" >&2; exit 1; fi
"$CLI" write -f transit/keys/demo/rotate >/dev/null
"$CLI" write -field=ciphertext transit/rewrap/demo ciphertext="$CT" >/dev/null
echo "   transit encrypt/decrypt/rotate/rewrap OK"

echo "==> Live cross-check completed."
