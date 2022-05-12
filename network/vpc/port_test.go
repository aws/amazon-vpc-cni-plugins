// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

// +build !integration_test,!e2e_test

package vpc

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidPortWithValidPort(t *testing.T) {
	ports := []string{"1", "65535", "1337", "311", " 1"}
	for _, port := range ports {
		result := ValidatePort(port)
		assert.NoError(t, result)
	}
}

func TestIsValidPortWithInvalidPort(t *testing.T) {
	ports := []string{"a", "1*ab", "-1", "1.1", "0", "65536", "", " "}
	for _, port := range ports {
		result := ValidatePort(port)
		assert.Equal(t, fmt.Sprintf("invalid port [%s] specified", port), result.Error())
	}
}

func TestIsValidPortRangeWithValidPort(t *testing.T) {
	ports := []int{1, 8080, 65535}
	for _, port := range ports {
		result := ValidatePortRange(port)
		assert.NoError(t, result)
	}
}

func TestIsValidPortRangeWithInValidPort(t *testing.T) {
	ports := []int{-200, -1, 0, 65536, 90000}
	for _, port := range ports {
		result := ValidatePortRange(port)
		assert.Equal(t, fmt.Sprintf("invalid port [%d] specified", port), result.Error())
	}
}
