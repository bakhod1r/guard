SHELL := /bin/bash
GOLANGCI_VERSION ?= v2.13.2
GOVULNCHECK_VERSION ?= v1.8.0
COMPOSE := docker compose -f examples/gin/docker-compose.yml
PKGS = $$(go list ./... | grep -v /examples/)

export GUARD_TEST_DATABASE_URL ?= postgres://postgres:postgres@localhost:18432/guard?sslmode=disable
export GUARD_TEST_REDIS_ADDR ?= localhost:18379

.PHONY: test test-integration cover lint vuln example example-down

test: ## unit tests (integration tests skip without GUARD_TEST_* services)
	go test -count=1 $(PKGS)

test-integration: ## start postgres+redis via compose, run race tests
	$(COMPOSE) up -d --wait postgres redis
	go test -count=1 -race -covermode=atomic -coverprofile=coverage.out $(PKGS)

cover: test-integration ## enforce 100.0% per package
	bash scripts/coverage-gate.sh coverage.out 100.0

lint:
	@if golangci-lint version 2>/dev/null | grep -q 'version 2\.'; then golangci-lint run ./...; \
	else go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION) run ./...; fi

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

example: ## full stack on :18080
	$(COMPOSE) up --build

example-down:
	$(COMPOSE) down -v
