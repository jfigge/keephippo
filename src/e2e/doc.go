// Package e2e holds end-to-end tests that spin up a real server on a random
// port and drive the full lifecycle (init → unseal → login → write → read →
// revoke) over HTTP. Run with `make e2e` (build tag: e2e).
package e2e
