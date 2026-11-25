# svc-admin build tasks. Generated code is committed; `make gen` regenerates it from a checkout of
# api-specs and records the api-specs commit in internal/gen/API_SPECS_COMMIT.
SHELL := /bin/bash
API_SPECS ?= ../api-specs
OAPI_CODEGEN_VERSION := v2.9.0
REDOCLY_VERSION := 2.83.0
TOOLS := $(CURDIR)/.tools/bin
BUNDLE := $(CURDIR)/.build/bundle
export PATH := $(TOOLS):$(PATH)
export GOPRIVATE := github.com/hostryhq/*

.PHONY: tools lint-tool gen lint vet test build

GOLANGCI_LINT_VERSION := v2.15.0

tools:
	GOBIN=$(TOOLS) go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION)

# The version CI pins (hostryhq/.github go-ci.yml).
lint-tool:
	GOBIN=$(TOOLS) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

# Bundle each spec (inlines shared $refs, output in the git-ignored .build/), then generate:
#   identity, tenancy, billing: types + client (what admin calls)
#   admin:             types + std-http-server (what admin serves)
# and extract operations and examples for the double and the upstream fakes.
gen: tools
	mkdir -p $(BUNDLE)
	for s in identity tenancy billing admin; do \
	  (cd $(API_SPECS) && npx --yes @redocly/cli@$(REDOCLY_VERSION) bundle openapi/$$s/v1/openapi.yaml -o $(BUNDLE)/$$s.yaml >/dev/null) || exit 1; \
	done
	for s in identity tenancy billing; do \
	  oapi-codegen -generate types,client -package $$s -o internal/gen/$$s/$$s.gen.go $(BUNDLE)/$$s.yaml || exit 1; \
	done
	oapi-codegen -generate types,std-http-server -package admin -o internal/gen/admin/admin.gen.go $(BUNDLE)/admin.yaml
	go run ./cmd/genspec -out internal/specdata $(BUNDLE)/identity.yaml $(BUNDLE)/tenancy.yaml $(BUNDLE)/billing.yaml $(BUNDLE)/admin.yaml
	git -C $(API_SPECS) rev-parse HEAD > internal/gen/API_SPECS_COMMIT
	test -z "$$(gofmt -l internal/gen)"

vet:
	go vet ./...

lint:
	golangci-lint run

test:
	go test -race -count=1 ./...

build:
	go build ./...
