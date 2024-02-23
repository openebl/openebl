TOPDIR := $(strip $(dir $(realpath $(lastword $(MAKEFILE_LIST)))))

CGO_ENABLED ?= 0
ifneq (,$(wildcard $(TOPDIR)/.env))
	include $(TOPDIR)/.env
	export
endif

comma:= ,
empty:=
space:= $(empty) $(empty)

bold := $(shell tput bold)
green := $(shell tput setaf 2)
sgr0 := $(shell tput sgr0)

MODULE_NAME := $(shell go list -m)

PLATFORM ?= $(platform)
ifneq ($(PLATFORM),)
	GOOS := $(or $(word 1, $(subst /, ,$(PLATFORM))),$(shell go env GOOS))
	GOARCH := $(or $(word 2, $(subst /, ,$(PLATFORM))),$(shell go env GOARCH))
endif

BIN_SUFFIX :=
ifneq ($(or $(GOOS),$(GOARCH)),)
	GOOS ?= $(shell go env GOOS)
	GOARCH ?= $(shell go env GOARCH)
	BIN_SUFFIX := $(BIN_SUFFIX)-$(GOOS)-$(GOARCH)
endif
ifeq ($(GOOS),windows)
	BIN_SUFFIX := $(BIN_SUFFIX).exe
endif

APPS := $(patsubst app/%/,%,$(sort $(dir $(wildcard app/*/))))
GOFILES := $(shell find . -type f -name '*.go' -not -path '*/\.*' -not -path './app/*')
$(foreach app,$(APPS),\
	$(eval GOFILES_$(app) := $(shell find ./app/$(app) -type f -name '*.go' -not -path '*/\.*')))

MOCK_DIR := test/mock
MOCK_SOURCES := \
	pkg/bu_server/storage/interface.go \
	pkg/bu_server/auth/api_key.go \
	pkg/bu_server/auth/application.go \
	pkg/bu_server/auth/user.go \
	pkg/bu_server/business_unit/bu_storage.go \
	pkg/bu_server/business_unit/bu_controller.go \
	pkg/bu_server/business_unit/bu_jws_signer.go \
	pkg/bu_server/cert_authority/cert_authority.go
MOCK_FILES := $(patsubst pkg/%,$(MOCK_DIR)/%,$(MOCK_SOURCES))

.DEFAULT: all

.PHONY: all
all: $(APPS)

.PHONY: $(APPS)
$(APPS): %: bin/%$(BIN_SUFFIX)

.PHONY: mock
mock: $(MOCK_FILES)

.PHONY: mock-clean
mock-clean:
	@$(RM) $(MOCK_FILES)
	@$(RM) -r $(MOCK_DIR)

$(MOCK_FILES): test/mock/% : pkg/%
	@mkdir -p $(@D)
	@printf "Generating $(bold)$@$(sgr0) ... "
	@mockgen -source $< -destination $@
	@printf "$(green)done$(sgr0)\n"

.SECONDEXPANSION:
bin/%: $$(GOFILES) $$(GOFILES_$$(@F))
	@printf "Building $(bold)$@$(sgr0) ... "
	@go build -o ./bin/$(@F) ./app/$(@F:$(BIN_SUFFIX)=)
	@printf "$(green)done$(sgr0)\n"

.PHONY: fmt
fmt: ## Reformat source codes
	@go fmt $$(go list ./... | grep -v -E "/test/mock/")
	@-gogroup -rewrite $$(find . -type f -name '*.go' -not -path '*/\.*' -not -path './test/mock/*')
	@-goimports -w $$(find . -type f -name '*.go' -not -path '*/\.*' -not -path './test/mock/*')
	@-goreturns -w $$(find . -type f -name '*.go' -not -path '*/\.*' -not -path './test/mock/*')

.PHONY: test
test: mock ## Run unit test
	@go clean -testcache
	@go test -p 1 -v -cover -covermode=count -coverprofile=coverage.out ./...
	@go tool cover -html coverage.out -o coverage.html
	@go tool cover -func coverage.out | tail -n 1

.PHONY: gosec
gosec: ## Run the golang security checker
	@gosec -exclude-dir test/mock ./...

.PHONY: platforms
platforms: ## Show available platforms
	@go tool dist list

.PHONY: clean
clean: ## Remove generated binary files
	@$(RM) -r bin

.PHONY: distclean
distclean: clean mock-clean ## Remove all generated files

.PHONY: help
help: ## Show this help
	@egrep -h '\s##\s' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

