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
	"fmt"
)

// Command is the option for plugin to print the version.
const Command = "version"

// Version is the version number of the repository.
var Version string

// GitShortHash is the short hash of the Git HEAD.
var GitShortHash string

// BuildTime is the build time stamp.
var BuildTime string

type versionInfo struct {
	Version      string `json:"version"`
	GitShortHash string `json:"gitShortHash"`
	Built        string `json:"built"`
}

// String returns a JSON version string from the versionInfo type.
func String() (string, error) {
	verInfo := versionInfo{
		Version:      Version,
		GitShortHash: GitShortHash,
		Built:        BuildTime,
	}

	verInfoJSON, err := json.Marshal(verInfo)
	if err != nil {
		return "", fmt.Errorf("version: failed to marshal version info: %v: %v", verInfo, err)
	}

	return string(verInfoJSON), nil
}
