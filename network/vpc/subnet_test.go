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

//go:build unit_test

package vpc

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	anySubnetPrefixString        = "12.34.56.0/22"
	anySubnetGateway             = "12.34.56.1"
	anyInvalidSubnetPrefixString = "12.345.56.0/42"
)

// TestNewSubnet tests subnet constructors.
func TestNewSubnet(t *testing.T) {
	_, anySubnetPrefix, _ := net.ParseCIDR(anySubnetPrefixString)

	// Subnet from valid IPNet.
	subnet, err := NewSubnet(anySubnetPrefix)
	assert.NoError(t, err)
	assert.Equal(t, anySubnetPrefixString, subnet.Prefix.String(), "incorrect prefix")
	assert.Equal(t, 1, len(subnet.Gateways), "incorrect number of gateways")
	assert.Equal(t, anySubnetGateway, subnet.Gateways[0].String(), "incorrect gateway")

	// Subnet from valid string.
	subnet, err = NewSubnetFromString(anySubnetPrefixString)
	assert.NoError(t, err)
	assert.Equal(t, anySubnetPrefixString, subnet.Prefix.String(), "incorrect prefix")
	assert.Equal(t, 1, len(subnet.Gateways), "incorrect number of gateways")
	assert.Equal(t, anySubnetGateway, subnet.Gateways[0].String(), "incorrect gateway")

	// Subnet from invalid string.
	subnet, err = NewSubnetFromString(anyInvalidSubnetPrefixString)
	assert.Error(t, err)
	assert.Nil(t, subnet)
}
