# Build paths.
ROOT := $(shell pwd)
SRC_DIR = .
BIN_DIR = ./bin
SOURCES := $(shell find $(SRC_DIR) -name '*.go')

# Plugins binaries.
VPC_BRANCH_ENI_PLUGIN_BINARY = $(BIN_DIR)/vpc-branch-eni
VPC_BRANCH_PAT_ENI_PLUGIN_BINARY = $(BIN_DIR)/vpc-branch-pat-eni

# Repo version.
VERSION ?= $(shell git describe --tags --always --dirty)
GIT_SHORT_HASH ?= $(shell git rev-parse --short HEAD 2> /dev/null)
GIT_PORCELAIN ?= $(shell git status --porcelain 2> /dev/null | wc -l)

.PHONY: build
build: plugins unit-test

.PHONY: plugins
plugins: vpc-branch-eni vpc-branch-pat-eni

.PHONY: vpc-branch-eni
vpc-branch-eni: $(VPC_BRANCH_ENI_PLUGIN_BINARY)

.PHONY: vpc-branch-pat-eni
vpc-branch-pat-eni: $(VPC_BRANCH_PAT_ENI_PLUGIN_BINARY)

$(VPC_BRANCH_ENI_PLUGIN_BINARY): $(SOURCES)
	GOOS=linux CGO_ENABLED=0 go build -installsuffix cgo -a -ldflags "\
	     -X github.com/aws/amazon-vpc-cni-plugins/pkg/version.GitShortHash=$(GIT_SHORT_HASH) \
	     -X github.com/aws/amazon-vpc-cni-plugins/pkg/version.GitPorcelain=$(GIT_PORCELAIN) \
	     -X github.com/aws/amazon-vpc-cni-plugins/pkg/version.Version=$(VERSION)" \
	     -o ${ROOT}/${VPC_BRANCH_ENI_PLUGIN_BINARY} github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-branch-eni
	@echo "Built vpc-branch-eni plugin"

$(VPC_BRANCH_PAT_ENI_PLUGIN_BINARY): $(SOURCES)
	GOOS=linux CGO_ENABLED=0 go build -installsuffix cgo -a -ldflags "\
	     -X github.com/aws/amazon-vpc-cni-plugins/pkg/version.GitShortHash=$(GIT_SHORT_HASH) \
	     -X github.com/aws/amazon-vpc-cni-plugins/pkg/version.GitPorcelain=$(GIT_PORCELAIN) \
	     -X github.com/aws/amazon-vpc-cni-plugins/pkg/version.Version=$(VERSION)" \
	     -o ${ROOT}/${VPC_BRANCH_PAT_ENI_PLUGIN_BINARY} github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-branch-pat-eni
	@echo "Built vpc-branch-pat-eni plugin"

.PHONY: unit-test
unit-test: $(SOURCES)
	go test -v -cover -race -timeout 10s ./...

.PHONY: clean
clean:
	rm -rf ${ROOT}/bin ||:
