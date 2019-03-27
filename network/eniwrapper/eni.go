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

package eniwrapper

import (
	"net"

	"github.com/aws/amazon-vpc-cni-plugins/network/eni"
)

// ENI wraps the methods in network/eni package to be used in testing.
type ENI interface {
	NewBranch(trunk *eni.Trunk, linkName string, macAddress net.HardwareAddr, isolationID int) (*eni.Branch, error)
	NewENI(linkName string, macAddress net.HardwareAddr) (*eni.ENI, error)
	NewTrunk(linkName string, macAddress net.HardwareAddr, isolationMode eni.IsolationMode) (*eni.Trunk, error)
}

type eniImpl struct {
}

// NewENI creates a new ENI object.
func NewENI() ENI {
	return &eniImpl{}
}

func (*eniImpl) NewBranch(trunk *eni.Trunk, linkName string, macAddress net.HardwareAddr, isolationID int) (*eni.Branch, error) {
	return eni.NewBranch(trunk, linkName, macAddress, isolationID)
}

func (*eniImpl) NewENI(linkName string, macAddress net.HardwareAddr) (*eni.ENI, error) {
	return eni.NewENI(linkName, macAddress)
}

func (*eniImpl) NewTrunk(linkName string, macAddress net.HardwareAddr, isolationMode eni.IsolationMode) (*eni.Trunk, error) {
	return eni.NewTrunk(linkName, macAddress, isolationMode)
}