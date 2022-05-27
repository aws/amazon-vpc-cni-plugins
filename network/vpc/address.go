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

// GetIPAddressFromString converts an IP address CIDR string to a net.IPNet structure.
func GetIPAddressFromString(ipAddress string) (*net.IPNet, error) {
	address, prefix, err := net.ParseCIDR(ipAddress)
	if err != nil {
		return nil, err
	}

	prefix.IP = address

	return prefix, nil
}

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

// ListContainsIPv4Address returns whether the given IP address list contains an IPv4 address.
func ListContainsIPv4Address(ipAddresses []net.IPNet) bool {
	for _, addr := range ipAddresses {
		if addr.IP.To4() != nil {
			return true
		}
	}
	return false
}

// ListContainsIPv6Address returns whether the given IP address list contains an IPv6 address.
func ListContainsIPv6Address(ipAddresses []net.IPNet) bool {
	for _, addr := range ipAddresses {
		if addr.IP.To4() == nil {
			return true
		}
	}
	return false
}
