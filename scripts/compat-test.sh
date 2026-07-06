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
export VAULT_ADDR="$ADDR" VAULT_TOKEN="$TOKEN"

"$BIN" secrets enable -path=secret kv >/dev/null
"$BIN" kv put secret/compat greeting=hello >/dev/null

echo "-- $CLI read secret/compat --"
"$CLI" read secret/compat

echo "==> Live cross-check completed."
