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

	"github.com/coreos/go-iptables/iptables"
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

// IsValidCIDR checks whether the input is a valid CIDR block and returns the IP protocol and validity
func IsValidCIDR(cidr string) (iptables.Protocol, bool) {
	// Check whether it is a valid CIDR block.
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return iptables.ProtocolIPv4, false
	}
	return getProtocol(ip)
}

// IsValidIPAddressOrCIDR checks whether the input is a valid IP addresses/CIDR block and returns the IP protocol and validity
func IsValidIPAddressOrCIDR(address string) (iptables.Protocol, bool) {
	ip := net.ParseIP(address)
	if ip == nil {
		// Check whether it is a valid CIDR block.
		return IsValidCIDR(address)
	}
	return getProtocol(ip)
}

// getProtocol returns the IP protocol and validity of the given input
func getProtocol(ip net.IP) (iptables.Protocol, bool) {
	if ip.To4() != nil {
		return iptables.ProtocolIPv4, true
	}
	if ip.To16() != nil {
		return iptables.ProtocolIPv6, true
	}
	return iptables.ProtocolIPv4, false
}
