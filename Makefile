# Repo-root Makefile — canonical local test gate for flokbn.
# Go module lives in $(GO_DIR); e2e suites delegate to e2e/Makefile.

GO_DIR := flokbn/src

.PHONY: test fmt-check fmt vet staticcheck go-test test-race e2e test-docker test-all bench

.DEFAULT_GOAL := test

# Canonical "run all tests": fmt → vet → staticcheck → go test → non-docker e2e.
# Excludes docker live tests (see test-docker / test-all).
test: fmt-check vet staticcheck go-test e2e
	@echo "==> All checks passed."

# Formatting
fmt-check:
	@echo "==> Running gofmt..."
	@cd $(GO_DIR) && UNFORMATTED=$$(gofmt -l .); \
	if [ -n "$$UNFORMATTED" ]; then \
		echo "ERROR: Go files not formatted:"; \
		echo "$$UNFORMATTED"; \
		echo "Run: gofmt -w ."; \
		exit 1; \
	fi

fmt:
	cd $(GO_DIR) && gofmt -w .

# Static analysis
vet:
	@echo "==> Running go vet..."
	cd $(GO_DIR) && go vet ./...

staticcheck:
	@echo "==> Running staticcheck..."
	cd $(GO_DIR) && staticcheck ./...

# Go tests
go-test:
	@echo "==> Running tests..."
	cd $(GO_DIR) && go test ./...

test-race:
	@echo "==> Running tests (race detector)..."
	cd $(GO_DIR) && go test -race ./...

# E2E suites (delegated to e2e/Makefile)
e2e:
	@echo "==> Running e2e suites (non-docker)..."
	$(MAKE) -C e2e all

test-docker:
	@echo "==> Running e2e suites (docker live)..."
	$(MAKE) -C e2e live live-detection live-firewall

# Full sweep: everything incl. race detector and docker live tests.
# Sequential sub-makes keep ordering deterministic under make -j.
test-all:
	$(MAKE) test && $(MAKE) test-race && $(MAKE) test-docker

# Package benchmarks (real-world benchmark is env-gated, run manually)
bench:
	cd $(GO_DIR) && go test -bench=. -benchmem ./...
