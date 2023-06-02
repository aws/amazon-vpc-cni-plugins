// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

//go:build unit_test

package vpc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestProtocolToNumberTCP tests the conversion of TCP protocol to number
// when the protocol is either in upper or lower case.
func TestProtocolToNumberTCP(t *testing.T) {
	protocolToTest := []string{"TCP", "tcp"}

	for _, testProtocol := range protocolToTest {
		actualProtocolNumber, err := ProtocolToNumber(testProtocol)
		assert.Equal(t, protocolTCP, actualProtocolNumber)
		assert.NoError(t, err)
	}
}

// TestProtocolToNumberUDP tests the conversion of UDP protocol to number
// when the protocol is either in upper or lower case.
func TestProtocolToNumberUDP(t *testing.T) {
	protocolToTest := []string{"UDP", "udp"}

	for _, testProtocol := range protocolToTest {
		actualProtocolNumber, err := ProtocolToNumber(testProtocol)
		assert.Equal(t, protocolUDP, actualProtocolNumber)
		assert.NoError(t, err)
	}
}

// TestProtocolToNumberFailure tests the failure case with invalid protocol.
func TestProtocolToNumberFailure(t *testing.T) {
	actualProtocolNumber, err := ProtocolToNumber("ICMP")
	assert.Equal(t, uint32(256), actualProtocolNumber)
	assert.Error(t, err)
}
