#!/usr/bin/env bash
# Generate a self-signed TLS certificate + key into testdata/ for local dev.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/src/testdata"
mkdir -p "$OUT"

openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout "$OUT/tls.key" -out "$OUT/tls.crt" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "wrote $OUT/tls.crt and $OUT/tls.key (git-ignored)"
