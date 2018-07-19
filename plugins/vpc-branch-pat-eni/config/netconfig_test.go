// +build !integration,!e2e

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

package config

import (
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/stretchr/testify/assert"
)

const (
	config = `
{
    "trunkName":"eth0",
    "branchVlanID":"101",
    "branchMACAddress":"01:23:45:67:89:ab",
    "branchIPAddress":"10.0.1.42/24",
    "cleanupPATNetNS": true
}
`
)

func TestValidConfig(t *testing.T) {
	args := &skel.CmdArgs{
		StdinData: []byte(config),
	}
	netConfig, err := New(args, false)
	assert.NoError(t, err)
	assert.Equal(t, "eth0", netConfig.TrunkName)
	assert.Equal(t, "101", netConfig.BranchVlanID)
	assert.Equal(t, "01:23:45:67:89:ab", netConfig.BranchMACAddress)
	assert.Equal(t, "10.0.1.42/24", netConfig.BranchIPAddress)
	assert.True(t, netConfig.CleanupPATNetNS)
}
