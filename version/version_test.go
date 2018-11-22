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

package version

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersionString(t *testing.T) {
	Version = "0.1.0"
	GitShortHash = "abcd"
	BuildTime = "2048-08-16T12:10:14-08:00"

	versionInfoJSON, err := String()
	assert.NoError(t, err)

	var retVersionInfo versionInfo
	json.Unmarshal([]byte(versionInfoJSON), &retVersionInfo)

	expectedVersionInfo := versionInfo{
		Version:      Version,
		GitShortHash: GitShortHash,
		Built:        BuildTime,
	}
	assert.Equal(t, retVersionInfo, expectedVersionInfo)
}
