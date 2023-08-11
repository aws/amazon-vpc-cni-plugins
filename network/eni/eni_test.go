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

//go:build unit_test

package eni

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetInterfaceByMacAddress(t *testing.T) {
	mac1, _ := net.ParseMAC("12:34:56:78:9a:bc")
	mac2, _ := net.ParseMAC("cb:a9:87:65:43:21")

	interfaces := []net.Interface{
		{
			Index:        1,
			Name:         "eth1.1",
			HardwareAddr: mac1,
		},
		{
			Index:        2,
			Name:         "eth1",
			HardwareAddr: mac1,
		},
		{
			Index:        3,
			Name:         "eth1.1.1",
			HardwareAddr: mac1,
		},
		{
			Index:        4,
			Name:         "eth",
			HardwareAddr: mac2,
		},
	}

	chosenInterface := getInterfaceByMACAddress(mac1, interfaces)
	assert.NotNil(t, chosenInterface)
	assert.Equal(t, "eth1", chosenInterface.Name)
}
