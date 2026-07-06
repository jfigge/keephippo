# syntax=docker/dockerfile:1
# Runtime image for keephippo, built and pushed by GoReleaser's dockers_v2
# (see src/.goreleaser.yaml). GoReleaser lays the per-platform static binaries
# out under <os>/<arch>/keephippo in the build context and drives a multi-arch
# `docker buildx build`, so this file selects the right one via the automatic
# $TARGETPLATFORM build arg (e.g. "linux/amd64"). OCI labels are attached by
# GoReleaser's build flags, so they stay in sync with the release version/commit.
#
# distroless/static:nonroot ships CA certs, tzdata, and an unprivileged user
# (uid 65532) but no shell or package manager — a small, low-surface base for a
# static Go binary.
FROM gcr.io/distroless/static:nonroot

ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/keephippo /usr/local/bin/keephippo

# keephippo's server listens on :8200 by default (internal/command/server.go).
# Bind the listener to 0.0.0.0:8200 in your config so it's reachable outside the
# container; the default 127.0.0.1 only accepts in-container connections.
EXPOSE 8200

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/keephippo"]
