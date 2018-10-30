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
BUILD_ROOT_DIR = build
BUILD_DIR = $(BUILD_ROOT_DIR)/$(GOOS)_$(GOARCH)
CREATE_BUILD_ROOT_DIR := $(shell mkdir -p $(BUILD_DIR))

# Git repo version.
GIT_TAG ?= $(shell git describe --tags --always --dirty)
GIT_SHORT_HASH ?= $(shell git rev-parse --short HEAD 2> /dev/null)
GIT_PORCELAIN ?= $(shell git status --porcelain 2> /dev/null | wc -l)
BUILD_VERSION ?= $(shell echo $(GIT_TAG) | sed 's/^v\([0-9]\)/\1/')
BUILD_RELEASE_FLAGS = "-a"
LINKER_FLAGS = "\
		-X github.com/aws/amazon-vpc-cni-plugins/version.GitShortHash=$(GIT_SHORT_HASH) \
		-X github.com/aws/amazon-vpc-cni-plugins/version.GitPorcelain=$(GIT_PORCELAIN) \
		-X github.com/aws/amazon-vpc-cni-plugins/version.Version=$(BUILD_VERSION) \
		-s"

# If we can't inspect the repo state, fall back to safe static strings.
ifeq ($(strip $(GIT_SHORT_HASH)),)
	GIT_SHORT_HASH=unknown
endif
ifeq ($(strip $(GIT_PORCELAIN)),)
	# This indicates that the repo is dirty.
	GIT_PORCELAIN=1
endif

# Source files.
COMMON_SOURCE_FILES = $(shell find . -name '*.go')
VPC_ENI_PLUGIN_SOURCE_FILES = $(wildcard plugins/vpc-eni/*.go)
VPC_SHARED_ENI_PLUGIN_SOURCE_FILES = $(wildcard plugins/vpc-eni/*.go)
VPC_BRANCH_ENI_PLUGIN_SOURCE_FILES = $(wildcard plugins/vpc-eni/*.go)
VPC_BRANCH_PAT_ENI_PLUGIN_SOURCE_FILES = $(wildcard plugins/vpc-branch-pat-eni/*.go)
ALL_SOURCE_FILES := $(shell find . -name '*.go')

# Shorthand build targets.
vpc-eni: $(BUILD_DIR)/vpc-eni
vpc-shared-eni: $(BUILD_DIR)/vpc-shared-eni
vpc-branch-eni: $(BUILD_DIR)/vpc-branch-eni
vpc-branch-pat-eni: $(BUILD_DIR)/vpc-branch-pat-eni
all-binaries: vpc-branch-eni vpc-branch-pat-eni
build: all-binaries unit-test

# Build the vpc-eni CNI plugin.
$(BUILD_DIR)/vpc-eni: $(VPC_ENI_PLUGIN_SOURCE_FILES) $(COMMON_SOURCE_FILES)
	go build \
		-installsuffix cgo \
		-v \
		-ldflags $(LINKER_FLAGS) \
		-o $(BUILD_DIR)/vpc-eni \
		github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-eni
	@echo "Built vpc-eni plugin."

# Build the vpc-shared-eni CNI plugin.
$(BUILD_DIR)/vpc-shared-eni: $(VPC_SHARED_ENI_PLUGIN_SOURCE_FILES) $(COMMON_SOURCE_FILES)
	go build \
		-installsuffix cgo \
		-v \
		-ldflags $(LINKER_FLAGS) \
		-o $(BUILD_DIR)/vpc-shared-eni \
		github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-shared-eni
	@echo "Built vpc-shared-eni plugin."

# Build the vpc-branch-eni CNI plugin.
$(BUILD_DIR)/vpc-branch-eni: $(VPC_BRANCH_ENI_PLUGIN_SOURCE_FILES) $(COMMON_SOURCE_FILES)
	go build \
		-installsuffix cgo \
		-v \
		-ldflags $(LINKER_FLAGS) \
		-o $(BUILD_DIR)/vpc-branch-eni \
		github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-branch-eni
	@echo "Built vpc-branch-eni plugin."

# Build the vpc-branch-pat-eni CNI plugin.
$(BUILD_DIR)/vpc-branch-pat-eni: $(VPC_BRANCH_PAT_ENI_PLUGIN_SOURCE_FILES) $(COMMON_SOURCE_FILES)
	go build \
		-installsuffix cgo \
		-v \
		-ldflags $(LINKER_FLAGS) \
		-o $(BUILD_DIR)/vpc-branch-pat-eni \
		github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-branch-pat-eni
	@echo "Built vpc-branch-pat-eni plugin."

# Run all unit tests.
.PHONY: unit-test
unit-test: $(ALL_SOURCE_FILES)
	go test -v -cover -race -timeout 10s ./...

# Run all integration tests.
.PHONY: integration-test
integration-test: $(ALL_SOURCE_FILES)
	go test -v -tags integration -race -timeout 10s ./...

# Clean all build artifacts.
.PHONY: clean
clean:
	rm -rf ${BUILD_ROOT_DIR} ||:
