#!/usr/bin/make -f

###############################################################################
###                           Module & Versioning                           ###
###############################################################################

VERSION ?= $(shell echo $(shell git describe --tags --always) | sed 's/^v//')
TMVERSION := $(shell go list -m github.com/cometbft/cometbft | sed 's:.* ::')
COMMIT := $(shell git log -1 --format='%H')

###############################################################################
###                          Directories & Binaries                         ###
###############################################################################

BINDIR ?= $(GOPATH)/bin
BUILDDIR ?= $(CURDIR)/build
EXAMPLE_BINARY := evmd

export GO111MODULE = on

###############################################################################
###                            Submodule Settings                           ###
###############################################################################`

# evmd is a separate module under ./evmd
EVMD_DIR      := evmd
EVMD_MAIN_PKG := ./cmd/evmd

###############################################################################
###                        Build & Install evmd                             ###
###############################################################################

# process build tags
build_tags = netgo

ifeq (cleveldb,$(findstring cleveldb,$(COSMOS_BUILD_OPTIONS)))
  build_tags += gcc
endif
build_tags += $(BUILD_TAGS)
build_tags := $(strip $(build_tags))

# process linker flags

ldflags = -X github.com/cosmos/cosmos-sdk/version.Name=os \
          -X github.com/cosmos/cosmos-sdk/version.AppName=$(EXAMPLE_BINARY) \
          -X github.com/cosmos/cosmos-sdk/version.Version=$(VERSION) \
          -X github.com/cosmos/cosmos-sdk/version.Commit=$(COMMIT) \
          -X github.com/cometbft/cometbft/version.TMCoreSemVer=$(TMVERSION)

# DB backend selection
ifeq (cleveldb,$(findstring cleveldb,$(COSMOS_BUILD_OPTIONS)))
  ldflags += -X github.com/cosmos/cosmos-sdk/types.DBBackend=cleveldb
endif

# add build tags to linker flags
whitespace := $(subst ,, )
comma := ,
build_tags_comma_sep := $(subst $(whitespace),$(comma),$(build_tags))
ldflags += -X "github.com/cosmos/cosmos-sdk/version.BuildTags=$(build_tags_comma_sep)"

ifeq (,$(findstring nostrip,$(COSMOS_BUILD_OPTIONS)))
  ldflags += -w -s
endif
ldflags += $(LDFLAGS)
ldflags := $(strip $(ldflags))

ifeq (staticlink,$(findstring staticlink,$(COSMOS_BUILD_OPTIONS)))
  ldflags += -linkmode external -extldflags '-static'
endif

BUILD_FLAGS := -tags "$(build_tags)" -ldflags '$(ldflags)'
# check for nostrip option
ifeq (,$(findstring nostrip,$(COSMOS_BUILD_OPTIONS)))
  BUILD_FLAGS += -trimpath
endif

# check if no optimization option is passed
# used for remote debugging
ifneq (,$(findstring nooptimization,$(COSMOS_BUILD_OPTIONS)))
  BUILD_FLAGS += -gcflags "all=-N -l"
endif

# Build into $(BUILDDIR)
build: $(EVMD_DIR)/go.sum $(BUILDDIR)/
	@echo "🏗️  Building evmd to $(BUILDDIR)/$(EXAMPLE_BINARY) ..."
	@cd $(EVMD_DIR) && CGO_ENABLED="1" \
	  go build $(BUILD_FLAGS) -o $(BUILDDIR)/$(EXAMPLE_BINARY) $(EVMD_MAIN_PKG)

# Cross-compile for Linux AMD64
build-linux:
	GOOS=linux GOARCH=amd64 $(MAKE) build

# Install into $(BINDIR)
install: $(EVMD_DIR)/go.sum
	@echo "🚚  Installing evmd to $(BINDIR) ..."
	@cd $(EVMD_DIR) && CGO_ENABLED="1" \
	  go install $(BUILD_FLAGS) $(EVMD_MAIN_PKG)

$(BUILDDIR)/:
	mkdir -p $(BUILDDIR)/

# Default & all target
.PHONY: all build build-linux install
all: build

###############################################################################
###                                Linting                                  ###
###############################################################################
golangci_lint_cmd=golangci-lint
golangci_version=v2.2.2

lint: lint-go

lint-go:
	@echo "--> Running linter"
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(golangci_version)
	@cd $(EVMD_DIR) && $(golangci_lint_cmd) run --timeout=15m -v

lint-fix:
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(golangci_version)
	@cd $(EVMD_DIR) && $(golangci_lint_cmd) run --timeout=15m --fix -v

.PHONY: lint lint-fix lint-go

format: format-go

format-go:
	find . -name '*.go' -type f -not -path "*.git*" | xargs gofumpt -w -l

.PHONY: format format-go

