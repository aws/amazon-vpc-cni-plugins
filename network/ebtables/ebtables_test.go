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

package ebtables

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	broadcastMACAddr, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
	randomMACAddr, _    = net.ParseMAC("12:34:56:78:9a:bc")
)

// TestSimpleRule tests a simple ebtables rule with a standard target.
func TestSimpleRule(t *testing.T) {
	assert.Equal(t,
		"ebtables -t filter -A INPUT -p IPv4 -i eth0 -j DROP",
		Filter.append(
			Input,
			&Rule{
				Protocol: "IPv4",
				In:       "eth0",
				Target:   Drop,
			},
		),
	)
}

// TestRuleWithARPMatch tests that rules with an ARP match extension are generated correctly.
func TestRuleWithARPMatch(t *testing.T) {
	assert.Equal(t,
		"ebtables -t nat -A PREROUTING -p ARP -i eth0 --arp-op Reply -j DROP",
		NAT.append(
			PreRouting,
			&Rule{
				Protocol: "ARP",
				In:       "eth0",
				Match: &ARPMatch{
					Op: "Reply",
				},
				Target: Drop,
			},
		),
	)
}

// TestRuleWithDNATTarget tests that rules with a DNAT target extension are generated correctly.
func TestRuleWithDNATTarget(t *testing.T) {
	assert.Equal(t,
		"ebtables -t nat -D PREROUTING -p IPv4 -i eth1 --ip-dst 10.1.1.42 -j dnat --to-dst 12:34:56:78:9a:bc --dnat-target ACCEPT",
		NAT.delete(
			PreRouting,
			&Rule{
				Protocol: "IPv4",
				In:       "eth1",
				Match: &IPv4Match{
					Dst: net.ParseIP("10.1.1.42"),
				},
				Target: &DNATTarget{
					ToDst:  randomMACAddr,
					Target: Accept,
				},
			},
		),
	)
}

// TestRuleWithSNATTarget tests that rules with an SNAT target extension are generated correctly.
func TestRuleWithSNATTarget(t *testing.T) {
	assert.Equal(t,
		"ebtables -t nat -A POSTROUTING -o eth2 -s unicast -j snat --to-src 12:34:56:78:9a:bc --snat-arp --snat-target ACCEPT",
		NAT.append(
			PostRouting,
			&Rule{
				Out:     "eth2",
				SrcType: "unicast",
				Target: &SNATTarget{
					ToSrc:  randomMACAddr,
					ARP:    true,
					Target: Accept,
				},
			},
		),
	)
}
