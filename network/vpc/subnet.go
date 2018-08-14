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

const (
	// JumboFrameMTU is the Jumbo Ethernet Frame Maximum Transmission Unit size in bytes.
	JumboFrameMTU = 9000
)

var (
	// Well-known VPC default gateway host ID.
	defaultGatewayHostID = []byte{0, 0, 0, 1}
)

// Subnet represents a VPC subnet.
type Subnet struct {
	Prefix   net.IPNet
	Gateways []net.IP
}

// NewSubnet creates a new VPC subnet object given its prefix.
func NewSubnet(prefix *net.IPNet) (*Subnet, error) {
	// Compute default gateway address.
	gateway := ComputeIPAddress(prefix, defaultGatewayHostID)

	subnet := &Subnet{
		Prefix:   *prefix,
		Gateways: []net.IP{gateway},
	}

	return subnet, nil
}

// NewSubnetFromString creates a new VPC subnet object given its prefix as a string.
func NewSubnetFromString(prefixString string) (*Subnet, error) {
	_, prefix, err := net.ParseCIDR(prefixString)
	if err != nil {
		return nil, err
	}

	subnet, err := NewSubnet(prefix)

	return subnet, err
}

// GetIPAddressFromString returns an IP address with prefix length.
func GetIPAddressFromString(ipAddress string) (*net.IPNet, error) {
	address, prefix, err := net.ParseCIDR(ipAddress)
	if err != nil {
		return nil, err
	}

	prefix.IP = address

	return prefix, nil
}

// ComputeIPAddress computes an IP address given its subnet prefix and host ID.
func ComputeIPAddress(prefix *net.IPNet, hostID net.IP) net.IP {
	// Always treat as IPv6 address to ensure compatibility with both IPv4 and IPv6.
	prefixIP := prefix.IP.To16()
	hostIP := hostID.To16()

	for i := 0; i < len(hostIP); i++ {
		hostIP[i] |= prefixIP[i]
	}

	return hostIP
}
