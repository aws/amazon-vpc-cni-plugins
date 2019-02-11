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

package capabilities

import (
	"encoding/json"
	"fmt"
)

const (
	// Command is the option for the plugin to print capabilities.
	Command = "capabilities"
	// TaskENICapability is the capability to support awsvpc network mode.
	TaskENICapability = "awsvpc-network-mode"
)

// Capability indicates the capability of a plugin.
type Capability struct {
	Capabilities []string `json:"capabilities,omitempty"`
}

// New returns a Capability object with specified capabilities.
func New(capabilities ...string) *Capability {
	return &Capability{
		Capabilities: capabilities,
	}
}

// String returns the JSON string of the Capability struct.
func (capability *Capability) String() (string, error) {
	data, err := json.Marshal(capability)
	if err != nil {
		return "", fmt.Errorf("capabilities: failed to marshal capabilities info %v: %v", capability.Capabilities, err)
	}

	return string(data), nil
}

// Print writes the supported capabilities info into the stdout.
func (capability *Capability) Print() error {
	info, err := capability.String()
	if err != nil {
		return err
	}

	fmt.Println(info)
	return nil
}