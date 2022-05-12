// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package test

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SetupPluginEnvironment sets up the environment for cni executable.
func SetupPluginEnvironment(t *testing.T, pluginName string) {
	// Create a directory for storing test logs.
	testLogDir, err := ioutil.TempDir("", pluginName+"-cni-e2eTests-test-")
	require.NoError(t, err, "Unable to create directory for storing test logs")

	// Configure the env var to use the test logs directory.
	os.Setenv("VPC_CNI_LOG_FILE", fmt.Sprintf("%s/%s.log", testLogDir, pluginName))
	t.Logf("Using %s for test logs", testLogDir)
	defer os.Unsetenv("VPC_CNI_LOG_FILE")

	// Handle deletion of test logs at the end of the test execution if specified.
	ok, err := strconv.ParseBool(getEnvOrDefault("ECS_PRESERVE_E2E_TEST_LOGS", "false"))
	assert.NoError(t, err, "Unable to parse ECS_PRESERVE_E2E_TEST_LOGS env var")
	defer func(preserve bool) {
		if !t.Failed() && !preserve {
			os.RemoveAll(testLogDir)
		}
	}(ok)
}

// getEnvOrDefault gets the value of an env var. It returns the fallback value
// if the env var is not set.
func getEnvOrDefault(name string, fallback string) string {
	val := os.Getenv(name)
	if val == "" {
		return fallback
	}

	return val
}
