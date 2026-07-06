#!/usr/bin/env bash
# Run a local dev server (in-memory storage, auto-unseal). Stub until Phase 1.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec go -C "$ROOT/src" run ./cmd/keephippo server -dev "$@"
