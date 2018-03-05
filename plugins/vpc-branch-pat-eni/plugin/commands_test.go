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

package plugin

import (
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

const (
	eniIPV4Address               = "10.11.12.13"
	eniIPV6Address               = "2001:db8::68"
	eniID                        = "eni1"
	deviceName                   = "eth1"
	nsName                       = "ns1"
	macAddressSanitized          = "mac1"
	eniIPV4Gateway               = "10.10.10.10"
	eniIPV6Gateway               = "2001:db9::68"
	eniIPV4SubnetMask            = "20"
	eniIPV6SubnetMask            = "32"
	mac                          = "01:23:45:67:89:ab"
	eniIPV4AddressWithSubnetMask = "10.11.12.13/20"
	eniIPV6AddressWithSubnetMask = "2001:db8::68/32"
)

var eniArgs = &skel.CmdArgs{
	StdinData: []byte(`{"cniVersion": "0.3.0",` +
		`"eni":"` + eniID +
		`", "ipv4-address":"` + eniIPV4Address +
		`", "mac":"` + mac +
		`", "ipv6-address":"` + eniIPV6Address +
		`"}`),
	Netns:  nsName,
	IfName: "eth0",
}

var eniArgsNoIPV6 = &skel.CmdArgs{
	StdinData: []byte(`{"cniVersion": "0.3.0",` +
		`"eni":"` + eniID +
		`", "ipv4-address":"` + eniIPV4Address +
		`", "mac":"` + mac +
		`"}`),
	Netns:  nsName,
	IfName: "eth0",
}

func TestAddWithInvalidConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mock_engine.NewMockEngine(ctrl)
	mockDHClient := mock_engine.NewMockDHClient(ctrl)

	err := add(&skel.CmdArgs{}, mockEngine, mockDHClient)
	assert.Error(t, err)
}
