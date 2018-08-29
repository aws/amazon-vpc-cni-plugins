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

package vpc

import (
	"net"
)

// CompareMACAddress returns whether two MAC addresses are equal.
func CompareMACAddress(addr1, addr2 net.HardwareAddr) bool {
	if len(addr1) != len(addr2) {
		return false
	}

	for i, octet := range addr1 {
		if octet != addr2[i] {
			return false
		}
	}

	return true
}
