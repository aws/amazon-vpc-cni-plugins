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

type config struct {
	netConfig string
	pcArgs    string
}

var (
	validConfigs = []config{
		config{ // All required fields in netconfig.
			netConfig: `{"trunkName":"eth0", "branchVlanID":"100", "branchMACAddress":"01:23:45:67:89:ab", "ipAddresses":["10.11.12.13/16"], "uid":"42", "gid":"42"}`,
			pcArgs:    "",
		},
		config{ // All required network fields in netconfig and branch fields in per-container args.
			netConfig: `{"trunkName":"eth1", "uid":"42", "gid":"42"}`,
			pcArgs:    "BranchVlanID=10;BranchMACAddress=10:20:30:40:50:60;IPAddresses=192.168.1.2/16",
		},
		config{ // TrunkMACAddress instead of TrunkName.
			netConfig: `{"trunkMACAddress":"42:42:42:42:42:42", "branchVlanID":"100", "branchMACAddress":"01:23:45:67:89:ab", "ipAddresses":["10.11.12.13/14"], "uid":"42", "gid":"42"}`,
			pcArgs:    "",
		},
		config{ // With multiple IP addresses.
			netConfig: `{"trunkName":"eth0", "branchVlanID":"100", "branchMACAddress":"01:23:45:67:89:ab", "ipAddresses":["10.11.12.13/16", "2001:1234::4/64"], "uid":"42", "gid":"42"}`,
			pcArgs:    "",
		},
		config{ // With multiple IP addresses in per-container args.
			netConfig: `{"trunkName":"eth0", "uid":"42", "gid":"42"}`,
			pcArgs:    "BranchVlanID=10;BranchMACAddress=10:20:30:40:50:60;IPAddresses=192.168.1.2/16,2001:1234::4/64;GatewayIPAddresses=192.168.1.1",
		},
		config{ // With optional fields.
			netConfig: `{"trunkMACAddress":"42:42:42:42:42:42", "blockInstanceMetadata":true, "interfaceType":"tap", "uid":"42", "gid":"42"}`,
			pcArgs:    "BranchVlanID=10;BranchMACAddress=10:20:30:40:50:60;IPAddresses=192.168.1.2/24;GatewayIPAddresses=192.168.1.1",
		},
		config{ // VLAN interface.
			netConfig: `{"trunkName":"eth1", "interfaceType": "vlan"}`,
			pcArgs:    "BranchVlanID=10;BranchMACAddress=10:20:30:40:50:60;IPAddresses=192.168.1.2/16",
		},
	}

	invalidConfigs = []config{
		config{ // invalid branch IP address.
			netConfig: `{"trunkName":"eth1", "uid":"42", "gid":"42"}`,
			pcArgs:    "BranchVlanID=100;BranchMACAddress=10:20:30:40:50:60;IPAddresses=192.168.1/16",
		},
		config{ // missing branch VLAN ID.
			netConfig: `{"trunkName":"eth1", "uid":"42", "gid":"42"}`,
			pcArgs:    "BranchMACAddress=10:20:30:40:50:60;IPAddresses=192.168.1.2/16",
		},
		config{ // missing TAP UID and GID.
			netConfig: `{"trunkName":"eth1", "branchVlanID":"100", "interfaceType":"tap"}`,
			pcArgs:    "BranchMACAddress=10:20:30:40:50:60;IPAddresses=192.168.1.2/16",
		},
	}
)

// TestValidConfigs tests that valid configs succeed.
func TestValidConfigs(t *testing.T) {
	for _, config := range validConfigs {
		args := &skel.CmdArgs{
			StdinData: []byte(config.netConfig),
			Args:      config.pcArgs,
		}
		_, err := New(args)
		assert.NoError(t, err)
	}
}

// TestInvalidConfigs tests that invalid configs fail.
func TestInvalidConfigs(t *testing.T) {
	for _, config := range invalidConfigs {
		args := &skel.CmdArgs{
			StdinData: []byte(config.netConfig),
			Args:      config.pcArgs,
		}
		_, err := New(args)
		assert.Error(t, err)
	}
}

// TestPerContainerArgsOverrideNetConfig tests that per-container args override per-network args.
func TestPerContainerArgsOverrideNetConfig(t *testing.T) {
	c := config{
		netConfig: `{"trunkName":"eth0", "branchVlanID":"100", "branchMACAddress":"01:23:45:67:89:ab", "ipAddresses":["10.11.12.13/14"], "uid":"42", "gid":"42"}`,
		pcArgs:    "BranchVlanID=42;BranchMACAddress=44:44:44:55:55:55;IPAddresses=192.168.1.2/16,2001:1234::4/64;GatewayIPAddresses=192.168.1.1,2001:1234::1",
	}

	args := &skel.CmdArgs{
		StdinData: []byte(c.netConfig),
		Args:      c.pcArgs,
	}
	nc, err := New(args)
	assert.NoError(t, err)

	assert.Equal(t, 42, nc.BranchVlanID, "invalid vlanid")
	assert.Equal(t, "44:44:44:55:55:55", nc.BranchMACAddress.String(), "invalid macaddress")

	assert.Equal(t, 2, len(nc.IPAddresses), "invalid number of ipaddresses")
	assert.Equal(t, "192.168.1.2/16", nc.IPAddresses[0].String(), "invalid ipaddresses")
	assert.Equal(t, "2001:1234::4/64", nc.IPAddresses[1].String(), "invalid ipaddresses")

	assert.Equal(t, 2, len(nc.GatewayIPAddresses), "invalid number of gatewayipaddresses")
	assert.Equal(t, "192.168.1.1", nc.GatewayIPAddresses[0].String(), "invalid gatewayipaddresses")
	assert.Equal(t, "2001:1234::1", nc.GatewayIPAddresses[1].String(), "invalid gatewayipaddresses")
}
