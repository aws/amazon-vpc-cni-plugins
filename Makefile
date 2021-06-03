# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the
# License is located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

# Build settings.
GOOS ?= linux
GOARCH ?= amd64
CGO_ENABLED = 0

# Build directories.
CUR_DIR = $(shell pwd)
BUILD_ROOT_DIR = build
BUILD_DIR = $(BUILD_ROOT_DIR)/$(GOOS)_$(GOARCH)
CREATE_BUILD_ROOT_DIR := $(shell mkdir -p $(BUILD_DIR))

# Git repo version.
GIT_TAG ?= $(shell git describe --tags --always --dirty)
GIT_SHORT_HASH ?= $(shell git rev-parse --short HEAD 2> /dev/null)
ifeq ($(strip $(GIT_SHORT_HASH)),)
	GIT_SHORT_HASH=unknown
endif

# Build version.
BUILD_VERSION ?= $(shell echo $(GIT_TAG) | sed 's/^v\([0-9]\)/\1/')
BUILD_TIMESTAMP = $(shell date +%Y-%m-%dT%H:%M:%S%z)
BUILD_RELEASE_FLAGS = -a
BUILD_FLAGS ?= $(BUILD_RELEASE_FLAGS)
LINKER_FLAGS = "\
		-X github.com/aws/amazon-vpc-cni-plugins/version.Version=$(BUILD_VERSION) \
		-X github.com/aws/amazon-vpc-cni-plugins/version.GitShortHash=$(GIT_SHORT_HASH) \
		-X github.com/aws/amazon-vpc-cni-plugins/version.BuildTime=$(BUILD_TIMESTAMP) \
		-s"

# Source files.
COMMON_SOURCE_FILES = $(wildcard capabilities/* cni/* logger/* network/*/* version/*)
VPC_ENI_PLUGIN_SOURCE_FILES = $(shell find plugins/vpc-eni -type f)
VPC_SHARED_ENI_PLUGIN_SOURCE_FILES = $(shell find plugins/vpc-shared-eni -type f)
VPC_BRANCH_ENI_PLUGIN_SOURCE_FILES = $(shell find plugins/vpc-branch-eni -type f)
VPC_BRANCH_PAT_ENI_PLUGIN_SOURCE_FILES = $(shell find plugins/vpc-branch-pat-eni -type f)
AWS_APPMESH_PLUGIN_SOURCE_FILES = $(shell find plugins/aws-appmesh -type f)
NETNSEXEC_TOOL_SOURCE_FILES = $(shell find tools/netnsexec -type f)
ALL_SOURCE_FILES := $(shell find . -name '*.go')

# Shorthand build targets.
vpc-eni: $(BUILD_DIR)/vpc-eni
vpc-shared-eni: $(BUILD_DIR)/vpc-shared-eni
vpc-branch-eni: $(BUILD_DIR)/vpc-branch-eni
vpc-branch-pat-eni: $(BUILD_DIR)/vpc-branch-pat-eni
aws-appmesh: $(BUILD_DIR)/aws-appmesh
netnsexec: $(BUILD_DIR)/netnsexec
all-plugins: vpc-eni vpc-shared-eni vpc-branch-eni vpc-branch-pat-eni aws-appmesh
all-tools: netnsexec
all-binaries: all-plugins all-tools
build: all-binaries unit-test

# Build the vpc-eni CNI plugin.
$(BUILD_DIR)/vpc-eni: $(VPC_ENI_PLUGIN_SOURCE_FILES) $(COMMON_SOURCE_FILES)
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) \
	go build \
		-installsuffix cgo \
		-v \
		$(BUILD_FLAGS) \
		-ldflags $(LINKER_FLAGS) \
		-o $(BUILD_DIR)/vpc-eni \
		github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-eni
	@echo "Built vpc-eni plugin."

# Build the vpc-shared-eni CNI plugin.
$(BUILD_DIR)/vpc-shared-eni: $(VPC_SHARED_ENI_PLUGIN_SOURCE_FILES) $(COMMON_SOURCE_FILES)
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) \
	go build \
		-installsuffix cgo \
		-v \
		$(BUILD_FLAGS) \
		-ldflags $(LINKER_FLAGS) \
		-o $(BUILD_DIR)/vpc-shared-eni \
		github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-shared-eni
	@echo "Built vpc-shared-eni plugin."

# Build the vpc-branch-eni CNI plugin.
$(BUILD_DIR)/vpc-branch-eni: $(VPC_BRANCH_ENI_PLUGIN_SOURCE_FILES) $(COMMON_SOURCE_FILES)
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) \
	go build \
		-installsuffix cgo \
		-v \
		$(BUILD_FLAGS) \
		-ldflags $(LINKER_FLAGS) \
		-o $(BUILD_DIR)/vpc-branch-eni \
		github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-branch-eni
	@echo "Built vpc-branch-eni plugin."

# Build the vpc-branch-pat-eni CNI plugin.
$(BUILD_DIR)/vpc-branch-pat-eni: $(VPC_BRANCH_PAT_ENI_PLUGIN_SOURCE_FILES) $(COMMON_SOURCE_FILES)
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) \
	go build \
		-installsuffix cgo \
		-v \
		$(BUILD_FLAGS) \
		-ldflags $(LINKER_FLAGS) \
		-o $(BUILD_DIR)/vpc-branch-pat-eni \
		github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-branch-pat-eni
	@echo "Built vpc-branch-pat-eni plugin."

# Build the aws-appmesh CNI plugin.
$(BUILD_DIR)/aws-appmesh: $(AWS_APPMESH_PLUGIN_SOURCE_FILES) $(COMMON_SOURCE_FILES)
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) \
	go build \
		-installsuffix cgo \
		-v \
		$(BUILD_FLAGS) \
		-ldflags $(LINKER_FLAGS) \
		-o $(BUILD_DIR)/aws-appmesh \
		github.com/aws/amazon-vpc-cni-plugins/plugins/aws-appmesh
	@echo "Built aws-appmesh plugin."

# Build the netnsexec tool.
$(BUILD_DIR)/netnsexec: $(NETNSEXEC_TOOL_SOURCE_FILES) $(COMMON_SOURCE_FILES)
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=$(CGO_ENABLED) \
	go build \
		-installsuffix cgo \
		-v \
		$(BUILD_FLAGS) \
		-ldflags $(LINKER_FLAGS) \
		-o $(BUILD_DIR)/netnsexec \
		github.com/aws/amazon-vpc-cni-plugins/tools/netnsexec
	@echo "Built netnsexec tool."

# Run all unit tests.
.PHONY: unit-test
unit-test: $(ALL_SOURCE_FILES)
	go test -v -cover -race -timeout 10s ./...

# Run aws-appmesh unit tests.
.PHONY: appmesh-unit-test
appmesh-unit-test:
	go test -v -cover -race -timeout 10s ./plugins/aws-appmesh/...

# Run all integration tests.
.PHONY: integration-test
integration-test: $(ALL_SOURCE_FILES)
	go test -v -tags integration_test -race -timeout 10s ./...

# Run all e2e tests.
.PHONY: e2e-test
e2e-test:  $(ALL_SOURCE_FILES) all-binaries
	sudo -E CNI_PATH=$(CUR_DIR)/$(BUILD_DIR) go test -v -tags e2e_test -race -timeout 120s ./...

.PHONY: vpc-branch-eni-e2e-tests
vpc-branch-eni-e2e-tests: $(ALL_SOURCE_FILES) vpc-branch-eni
	sudo -E CNI_PATH=$(CUR_DIR)/$(BUILD_DIR) go test -v -tags "e2e_test vpc_branch_eni" -race -timeout 60s ./plugins/vpc-branch-eni/e2eTests/

# Clean all build artifacts.
.PHONY: clean
clean:
	rm -rf ${BUILD_ROOT_DIR} ||:
