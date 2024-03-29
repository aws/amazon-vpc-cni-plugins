// Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

//go:build unit_test

package logger

import (
	"os"
	"testing"

	log "github.com/cihub/seelog"
	"github.com/stretchr/testify/assert"
)

func TestGetLogFilePathReturnsOverriddenPath(t *testing.T) {
	path := "/tmp/foo"
	os.Setenv(envLogFilePath, path)
	defer os.Unsetenv(envLogFilePath)

	assert.Equal(t, path, getLogFilePath("/tmp/bar"))
}

func TestGetLogFilePathReturnsDefaultPath(t *testing.T) {
	path := "/tmp/foo"
	assert.Equal(t, path, getLogFilePath(path))
}

func TestLogLevelReturnsOverriddenLevel(t *testing.T) {
	os.Setenv(envLogLevel, "debug")
	defer os.Unsetenv(envLogLevel)

	var expectedLogLevel log.LogLevel
	expectedLogLevel = log.DebugLvl
	assert.Equal(t, expectedLogLevel.String(), getLogLevel())
}

func TestLogLevelReturnsDefaultLevelWhenEnvNotSet(t *testing.T) {
	var expectedLogLevel log.LogLevel
	expectedLogLevel = log.InfoLvl
	assert.Equal(t, expectedLogLevel.String(), getLogLevel())
}

func TestLogLevelReturnsDefaultLevelWhenEnvSetToInvalidValue(t *testing.T) {
	os.Setenv(envLogLevel, "DEBUGGER")
	defer os.Unsetenv(envLogLevel)

	var expectedLogLevel log.LogLevel
	expectedLogLevel = log.InfoLvl
	assert.Equal(t, expectedLogLevel.String(), getLogLevel())
}
