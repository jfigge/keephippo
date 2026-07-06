#!/usr/bin/env bash
# Cut a release: validate → confirm on main & in sync → gate on tests →
# fast-forward the 'release' branch → tag → push. Invoked by `make release`.
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" || "$VERSION" == "dev" ]]; then
  echo "usage: make release VERSION=1.2.3" >&2
  exit 2
fi

# Accept 1.2.3 or v1.2.3; normalize to a bare semver.
VERSION="${VERSION#v}"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]]; then
  echo "error: VERSION must be semver (e.g. 1.2.3), got '$VERSION'" >&2
  exit 2
fi
TAG="v$VERSION"

branch="$(git rev-parse --abbrev-ref HEAD)"
[[ "$branch" == "main" ]] || { echo "error: releases are cut from 'main' (on '$branch')" >&2; exit 1; }
[[ -z "$(git status --porcelain)" ]] || { echo "error: working tree is dirty; commit or stash first" >&2; exit 1; }

git fetch --tags --quiet origin
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  echo "error: tag $TAG already exists" >&2
  exit 1
fi
if [[ "$(git rev-list --count "HEAD..origin/main" 2>/dev/null || echo 0)" != "0" ]]; then
  echo "error: local main is behind origin/main; pull/rebase first" >&2
  exit 1
fi

echo "==> Running tests before tagging"
make test

echo
read -r -p "Tag $TAG and push main + release + tag to origin? [y/N] " ans
[[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "aborted"; exit 1; }

git branch -f release main
git tag -a "$TAG" -m "Release $TAG"
git push origin main
git push origin release
git push origin "$TAG"
echo "==> Pushed $TAG. The Release workflow will build and publish artifacts."
