# keephippo — authoritative command list.
# `make help` for a summary. Default target: clean → fmt → lint → test → build.
#
# The Go application source lives under ./src (the module root); everything else
# in the repo is project/support tooling. Go commands run with `-C $(SRC)`.

GO         ?= go
MODULE     := github.com/jfigge/keephippo
BIN        := keephippo
SRC        := src
PKG        := ./cmd/keephippo
BUILD_DIR  := $(CURDIR)/build
DIST_DIR   := $(CURDIR)/dist
VERPKG     := $(MODULE)/internal/version

# ---- version metadata (injected via -ldflags) ----
# VERSION defaults to the git description; override it for a release:
#   make release VERSION=1.2.3
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BRANCH     := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo none)
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w \
	-X $(VERPKG).Version=$(VERSION) \
	-X $(VERPKG).Commit=$(COMMIT) \
	-X $(VERPKG).Branch=$(BRANCH) \
	-X $(VERPKG).BuildTime=$(BUILD_TIME)

# Optional env files (git-ignored). release.env holds signing creds; when it is
# absent, the sign-* targets degrade to unsigned no-ops.
-include dev.env
-include release.env

.DEFAULT_GOAL := all

.PHONY: all help version info install debug dev fmt fmt-check lint test e2e compat vuln \
	build build-mac build-linux build-win dist dist-mac dist-linux dist-win \
	sign-mac sign-win release dev-certs clean

# ---- meta ----
all: clean fmt lint test build ## Full pipeline: clean → fmt → lint → test → build

help: ## List all targets
	@grep -hE '^[a-zA-Z0-9_.-]+:.*## ' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN{FS=":.*## "}{printf "  \033[36m%-13s\033[0m %s\n", $$1, $$2}'

version: ## Print the version string
	@echo "$(VERSION)"

info: ## Print version + branch + commit + build time
	@echo "version:    $(VERSION)"
	@echo "branch:     $(BRANCH)"
	@echo "commit:     $(COMMIT)"
	@echo "build time: $(BUILD_TIME)"
	@echo "go:         $$($(GO) version)"

# ---- dev ----
install: ## Download deps and install dev tools (gofumpt, golangci-lint, govulncheck, goreleaser)
	$(GO) -C $(SRC) mod download
	$(GO) install mvdan.cc/gofumpt@latest
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	$(GO) install github.com/goreleaser/goreleaser/v2@latest

debug: ## Run a dev server (in-mem, auto-unseal) — stub until Phase 1
	$(GO) -C $(SRC) run $(PKG) server -dev

dev: debug ## Alias for debug (prints root token + unseal key) — stub until Phase 1

# ---- quality ----
fmt: ## Format code (gofumpt if available, else gofmt)
	@if command -v gofumpt >/dev/null 2>&1; then \
		gofumpt -w $(SRC) ; \
	else \
		echo "gofumpt not installed; using gofmt (run 'make install' for gofumpt)"; \
		$(GO) -C $(SRC) fmt ./... ; \
	fi

fmt-check: ## Fail if any file is unformatted
	@if command -v gofumpt >/dev/null 2>&1; then FMT=gofumpt; else FMT=gofmt; echo "gofumpt not installed; falling back to gofmt"; fi; \
	out=$$($$FMT -l $(SRC) 2>/dev/null); \
	if [ -n "$$out" ]; then echo "Unformatted files:"; echo "$$out"; exit 1; fi; \
	echo "formatting OK"

lint: ## Run golangci-lint (skipped with a warning if not installed)
	@if command -v golangci-lint >/dev/null 2>&1; then \
		cd $(SRC) && golangci-lint run ; \
	else \
		echo "golangci-lint not installed; skipping (run 'make install'). CI runs it for real."; \
	fi

test: ## Run unit tests with the race detector + coverage
	$(GO) -C $(SRC) test ./... -race -cover

e2e: ## Run the e2e integration suite — stub until later phases
	$(GO) -C $(SRC) test -tags=e2e -race -count=1 ./e2e/...

compat: ## Run the openbao/vault CLI against our server — stub until Phase 2
	@echo "compat: not yet implemented (Phase 2)"

vuln: ## Run govulncheck (skipped with a warning if not installed)
	@if command -v govulncheck >/dev/null 2>&1; then \
		cd $(SRC) && govulncheck ./... ; \
	else \
		echo "govulncheck not installed; skipping (run 'make install'). CI runs it for real."; \
	fi

# ---- build (host platform, unsigned, fast) ----
build: ## Build the binary for the host OS/arch → build/keephippo
	$(GO) -C $(SRC) build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BIN) $(PKG)

build-mac: ## Build darwin amd64 + arm64
	GOOS=darwin GOARCH=amd64 $(GO) -C $(SRC) build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BIN)-darwin-amd64 $(PKG)
	GOOS=darwin GOARCH=arm64 $(GO) -C $(SRC) build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BIN)-darwin-arm64 $(PKG)

build-linux: ## Build linux amd64 + arm64
	GOOS=linux GOARCH=amd64 $(GO) -C $(SRC) build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BIN)-linux-amd64 $(PKG)
	GOOS=linux GOARCH=arm64 $(GO) -C $(SRC) build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BIN)-linux-arm64 $(PKG)

build-win: ## Build windows amd64 + arm64
	GOOS=windows GOARCH=amd64 $(GO) -C $(SRC) build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BIN)-windows-amd64.exe $(PKG)
	GOOS=windows GOARCH=arm64 $(GO) -C $(SRC) build -trimpath -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BIN)-windows-arm64.exe $(PKG)

# ---- dist (cross-platform archives via GoReleaser) ----
dist: ## Build all OS/arch archives (snapshot, unsigned) via GoReleaser
	@if command -v goreleaser >/dev/null 2>&1; then cd $(SRC) && goreleaser build --snapshot --clean; else echo "goreleaser not installed (run 'make install')"; exit 1; fi

dist-mac: build-mac ## Archive darwin builds into dist/
	@mkdir -p $(DIST_DIR)
	@cd $(BUILD_DIR) && for a in $(BIN)-darwin-amd64 $(BIN)-darwin-arm64; do tar -czf $(DIST_DIR)/$$a.tar.gz $$a; done
	@echo "wrote dist/*.tar.gz"

dist-linux: build-linux ## Archive linux builds into dist/
	@mkdir -p $(DIST_DIR)
	@cd $(BUILD_DIR) && for a in $(BIN)-linux-amd64 $(BIN)-linux-arm64; do tar -czf $(DIST_DIR)/$$a.tar.gz $$a; done
	@echo "wrote dist/*.tar.gz"

dist-win: build-win ## Archive windows builds into dist/
	@mkdir -p $(DIST_DIR)
	@cd $(BUILD_DIR) && for a in $(BIN)-windows-amd64.exe $(BIN)-windows-arm64.exe; do zip -q $(DIST_DIR)/$${a%.exe}.zip $$a; done
	@echo "wrote dist/*.zip"

# ---- signing (reads release.env; no-op when creds absent) ----
sign-mac: ## codesign + notarize macOS artifacts (no-op if creds absent)
	@if [ -z "$(MACOS_SIGN_IDENTITY)" ]; then \
		echo "sign-mac: no signing identity (release.env absent); skipping (unsigned)"; \
	else \
		echo "sign-mac: would codesign+notarize with '$(MACOS_SIGN_IDENTITY)' (release pipeline)"; \
	fi

sign-win: ## Authenticode-sign Windows artifacts (no-op if creds absent)
	@if [ -z "$(WINDOWS_CERT_FILE)" ]; then \
		echo "sign-win: no signing cert (release.env absent); skipping (unsigned)"; \
	else \
		echo "sign-win: would Authenticode-sign with '$(WINDOWS_CERT_FILE)' (release pipeline)"; \
	fi

# ---- release ----
release: ## Cut a release: make release VERSION=1.2.3
	@./scripts/release.sh "$(VERSION)"

# ---- helpers ----
dev-certs: ## Generate self-signed TLS certs into src/testdata/
	@./scripts/gen-cert.sh

clean: ## Remove build/ and dist/
	@rm -rf $(BUILD_DIR) $(DIST_DIR)
	@echo "cleaned"
