// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

//go:build !integration_test && !e2e_test
// +build !integration_test,!e2e_test

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
		{ // All required fields in netconfig.
			netConfig: `{"destinationIPAddress":"10.0.2.129", "vni":"CB0CF5", "destinationPort":"6081", "primary":true, "ipAddresses":["169.254.0.1/31"], "gatewayIPAddress": "169.254.0.0", "uid":"42", "gid":"42"}`,
			pcArgs:    "",
		},
		{ // All required network fields in netconfig and GENEVE fields in per-container args.
			netConfig: `{"uid":"42", "gid":"42"}`,
			pcArgs:    "DestinationIPAddress=10.0.2.129;VNI=CB0CF5;DestinationPort=6081;IPAddresses=169.254.0.1/31;GatewayIPAddress=169.254.0.0;Primary=true",
		},
		{ // With multiple IP addresses.
			netConfig: `{"destinationIPAddress":"10.0.2.129", "vni":"CB0CF5", "destinationPort":"6081", "ipAddresses":["169.254.0.1/29", "169.254.0.2/29"], "gatewayIPAddress": "169.254.0.3", "uid":"42", "gid":"42"}`,
			pcArgs:    "",
		},
		{ // With multiple IP addresses in per-container args.
			netConfig: `{"uid":"42", "gid":"42"}`,
			pcArgs:    "DestinationIPAddress=10.0.2.129;VNI=CB0CF5;DestinationPort=6081;IPAddresses=169.254.0.1/29,169.254.0.2/29;GatewayIPAddress=169.254.0.3",
		},
		{ // With optional fields.
			netConfig: `{"blockInstanceMetadata":true, "interfaceType":"tap", "uid":"42", "gid":"42"}`,
			pcArgs:    "DestinationIPAddress=10.0.2.129;VNI=CB0CF5;DestinationPort=6081;IPAddresses=169.254.0.1/31;GatewayIPAddress=169.254.0.0",
		},
		{ // GENEVE interface.
			netConfig: `{"interfaceType":"geneve"}`,
			pcArgs:    "DestinationIPAddress=10.0.2.129;VNI=CB0CF5;DestinationPort=6081;IPAddresses=169.254.0.1/31;GatewayIPAddress=169.254.0.0",
		},
	}

	invalidConfigs = []config{
		{ // invalid destination IP address.
			netConfig: `{"destinationIPAddress":"", "vni":"CB0CF5", "destinationPort":"6081", "ipAddresses":["169.254.0.1/31"], "gatewayIPAddress": "169.254.0.0", "uid":"42", "gid":"42"}`,
			pcArgs:    "",
		},
		{ // missing destination port.
			netConfig: `{"destinationIPAddress":"10.0.2.129", "vni":"CB0CF5", "ipAddresses":["169.254.0.1/31"], "gatewayIPAddress": "169.254.0.0", "uid":"42", "gid":"42"}`,
			pcArgs:    "",
		},
		{ // missing VNI.
			netConfig: `{"uid":"42", "gid":"42"}`,
			pcArgs:    "DestinationIPAddress=10.0.2.129;DestinationPort=6081;IPAddresses=169.254.0.1/31;GatewayIPAddress=169.254.0.0",
		},
		{ // missing TAP UID and GID.
			netConfig: `{"interfaceType":"tap"}`,
			pcArgs:    "DestinationIPAddress=10.0.2.129;VNI=CB0CF5;DestinationPort=6081;IPAddresses=169.254.0.1/31;GatewayIPAddress=169.254.0.0",
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
		netConfig: `{"destinationIPAddress":"10.0.2.129", "vni":"CB0CF5", "destinationPort":"6081", "primary": true, "ipAddresses":["169.254.0.1/31"], "gatewayIPAddress": "169.254.0.0", "uid":"42", "gid":"42"}`,
		pcArgs:    "DestinationIPAddress=10.0.2.130;VNI=CB0CF6;DestinationPort=6082;IPAddresses=169.254.0.1/29,169.254.0.2/29;GatewayIPAddress=169.254.0.3;Primary=false",
	}

	args := &skel.CmdArgs{
		StdinData: []byte(c.netConfig),
		Args:      c.pcArgs,
	}
	nc, err := New(args)
	assert.NoError(t, err)

	assert.Equal(t, "10.0.2.130", nc.DestinationIPAddress.String(), "invalid destination IP address")
	assert.Equal(t, "CB0CF6", nc.VNI, "invalid VNI")
	assert.Equal(t, uint16(6082), nc.DestinationPort, "invalid destination port")
	assert.Equal(t, false, nc.Primary, "invalid primary flag")

	assert.Equal(t, 2, len(nc.IPAddresses), "invalid number of ipaddresses")
	assert.Equal(t, "169.254.0.1/29", nc.IPAddresses[0].String(), "invalid ipaddresses")
	assert.Equal(t, "169.254.0.2/29", nc.IPAddresses[1].String(), "invalid ipaddresses")

	assert.Equal(t, "169.254.0.3", nc.GatewayIPAddress.String(), "invalid gatewayipaddress")
}
