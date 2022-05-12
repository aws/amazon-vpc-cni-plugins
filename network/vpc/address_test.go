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

// +build !integration_test,!e2e_test

package vpc

import (
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/assert"
)

func TestIsValidIPAddressOrCIDR(t *testing.T) {
	type IPAddr struct {
		ip            string
		expectedProto iptables.Protocol
		expectedValid bool
	}
	ips := []IPAddr{
		{ip: "216.3.128.12", expectedProto: iptables.ProtocolIPv4, expectedValid: true},
		{ip: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", expectedProto: iptables.ProtocolIPv6, expectedValid: true},
		{ip: "2001:0db8::0000:0000:8a2e:0370:7334", expectedProto: iptables.ProtocolIPv6, expectedValid: true},
		{ip: "216.3.128.12/24", expectedProto: iptables.ProtocolIPv4, expectedValid: true},
		{ip: "2001:0db8:85a3:0000:0000:8a2e:0370:7334/32", expectedProto: iptables.ProtocolIPv6, expectedValid: true},
		{ip: "a", expectedProto: iptables.ProtocolIPv4, expectedValid: false},
		{ip: "1*ab", expectedProto: iptables.ProtocolIPv4, expectedValid: false},
		{ip: "123.222.333.444/24", expectedProto: iptables.ProtocolIPv4, expectedValid: false},
		{ip: "123.222..444", expectedProto: iptables.ProtocolIPv4, expectedValid: false},
		{ip: "123.222/333.444", expectedProto: iptables.ProtocolIPv4, expectedValid: false},
	}
	for _, ip := range ips {
		proto, valid := IsValidIPAddressOrCIDR(ip.ip)
		assert.Equal(t, ip.expectedProto, proto)
		assert.Equal(t, ip.expectedValid, valid)
	}
}

func TestIsValidCIDR(t *testing.T) {
	type CIDRAddr struct {
		cidr          string
		expectedProto iptables.Protocol
		expectedValid bool
	}
	cidrs := []CIDRAddr{
		{cidr: "127.255.0.0/16", expectedProto: iptables.ProtocolIPv4, expectedValid: true},
		{cidr: "2600:f0f0::/96", expectedProto: iptables.ProtocolIPv6, expectedValid: true},
		{cidr: "2002::1234:abcd:ffff:c0a8:101/64", expectedProto: iptables.ProtocolIPv6, expectedValid: true},
		{cidr: "216.3.128.12", expectedProto: iptables.ProtocolIPv4, expectedValid: false},
		{cidr: "2001:0db8:85a3:0000:0000:8a2e:0370:7334/32", expectedProto: iptables.ProtocolIPv6, expectedValid: true},
		{cidr: "2001:0db8:AC10:FE01::", expectedProto: iptables.ProtocolIPv4, expectedValid: false},
		{cidr: "127.255.255.255/96", expectedProto: iptables.ProtocolIPv4, expectedValid: false},
		{cidr: "123.222/333.444", expectedProto: iptables.ProtocolIPv4, expectedValid: false},
		{cidr: "2600:f0f0::/96/32", expectedProto: iptables.ProtocolIPv4, expectedValid: false},
	}
	for _, cidr := range cidrs {
		proto, valid := IsValidCIDR(cidr.cidr)
		assert.Equal(t, cidr.expectedProto, proto)
		assert.Equal(t, cidr.expectedValid, valid)
	}
}
