// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
	"net"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/pkg/errors"
)

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

// ValidatePort checks whether the port only has digits and is within valid port range
func ValidatePort(p string) error {
	port := strings.TrimSpace(p)

	if i, err := strconv.Atoi(port); err == nil {
		return ValidatePortRange(i)
	}
	return errors.Errorf("invalid port [%s] specified", p)
}

// ValidatePortRange checks whether the given port is within valid port range
func ValidatePortRange(port int) error {
	if port > 0 && port <= 65535 {
		return nil
	}
	return errors.Errorf("invalid port [%d] specified", port)
}
