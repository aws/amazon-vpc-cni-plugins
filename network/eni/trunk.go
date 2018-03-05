// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package eni

import (
	"fmt"
	"net"

	log "github.com/cihub/seelog"
)

// IsolationMode represents the trunk's isolation mode.
type IsolationMode uint

const (
	TrunkIsolationModeVLAN    IsolationMode = 1
	TrunkIsolationModeGRE     IsolationMode = 2
	TrunkIsolationModeDefault IsolationMode = TrunkIsolationModeVLAN
)

// Trunk represents a VPC trunk ENI.
type Trunk struct {
	ENI
	isolationMode IsolationMode
	branches      []Branch
}

// NewTrunk creates a new Trunk object.
func NewTrunk(linkName string, isolationMode IsolationMode) (*Trunk, error) {
	if isolationMode != TrunkIsolationModeVLAN {
		log.Errorf("Invalid isolation mode: %v", isolationMode)
		return nil, fmt.Errorf("Invalid isolation mode")
	}

	trunkInterface, err := net.InterfaceByName(linkName)
	if err != nil {
		log.Errorf("Failed to find trunk interface %s: %v", linkName, err)
		return nil, fmt.Errorf("Invalid link name")
	}

	trunk := &Trunk{
		ENI: ENI{
			linkIndex: trunkInterface.Index,
			linkName:  linkName,
		},
		isolationMode: isolationMode,
	}

	return trunk, nil
}
