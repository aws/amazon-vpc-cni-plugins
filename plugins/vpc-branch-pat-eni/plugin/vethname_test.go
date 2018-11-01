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

package plugin

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateVethPairNames(t *testing.T) {
	testCases := []struct {
		name               string
		containerID        string
		vlanID             int
		validateNames      bool
		expectedVethName   string
		generateRandomName bool
	}{
		{
			name:               "short container ID generates predictable veth name",
			containerID:        "abc",
			vlanID:             100,
			validateNames:      true,
			expectedVethName:   "ve100-abc",
			generateRandomName: false,
		},
		{
			name:               "long container ID generates short veth name",
			containerID:        "abc-70d92ae9-8de6-4d02-aa85-063add9b7e0b",
			vlanID:             100,
			validateNames:      false,
			expectedVethName:   "",
			generateRandomName: false,
		},
		{
			name:               "short container ID generates random veth name when specified",
			containerID:        "abc",
			vlanID:             100,
			validateNames:      false,
			expectedVethName:   "",
			generateRandomName: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			veth, peer := generateVethPairNames(tc.vlanID, tc.containerID, tc.generateRandomName)
			assert.True(t, len(veth) <= maxAllowedIfNameLength, "veth device length exceeds %d: %s",
				maxAllowedIfNameLength, veth)
			assert.True(t, len(peer) <= maxAllowedIfNameLength, "veth device length exceeds %d: %s",
				maxAllowedIfNameLength, peer)
			if tc.validateNames {
				assert.Equal(t, veth, tc.expectedVethName)
				assert.Equal(t, peer, tc.expectedVethName+"-2")
			} else {
				assert.NotEqual(t, veth, tc.expectedVethName)
				assert.NotEqual(t, peer, tc.expectedVethName+"-2")
			}

		})
	}
}

func TestVethPeerNameRecognizable(t *testing.T) {
	testCases := []struct {
		vethPeerName string
		matches      bool
	}{
		{
			vethPeerName: "ve100-asasa-2",
			matches:      true,
		},
		{
			vethPeerName: "ave100-asasa-2",
			matches:      false,
		},
		{
			vethPeerName: "veth-asasa-2",
			matches:      false,
		},
		{
			vethPeerName: "ve100-asasa",
			matches:      false,
		},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s match should be %t", tc.vethPeerName, tc.matches), func(t *testing.T) {
			assert.Equal(t, tc.matches, vethPeerNameRecognizable(tc.vethPeerName))
		})
	}
}
