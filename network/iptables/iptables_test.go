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

package iptables

import (
	"fmt"
	"testing"
)

func TestAppend(t *testing.T) {
	s, err := NewSession()
	if err != nil {
		t.Fail()
		return
	}

	s.Mangle.Postrouting.Append("-o virbr0 -p udp -m udp --dport 68 -j CHECKSUM --checksum-fill")

	s.Nat.Postrouting.Append("-s #{pat_bridge_interface_subnet_cidr} -d 224.0.0.0/24 -o #{pat_branch_interface_name} -j RETURN")
	s.Nat.Postrouting.Append("-s #{pat_bridge_interface_subnet_cidr} -d 255.255.255.255/32 -o #{pat_branch_interface_name} -j RETURN")
	s.Nat.Postrouting.Append("-s #{pat_bridge_interface_subnet_cidr} ! -d #{pat_bridge_interface_subnet_cidr} -o #{pat_branch_interface_name} -p tcp -j MASQUERADE --to-ports 1024-65535")
	s.Nat.Postrouting.Append("-s #{pat_bridge_interface_subnet_cidr} ! -d #{pat_bridge_interface_subnet_cidr} -o #{pat_branch_interface_name} -p udp -j MASQUERADE --to-ports 1024-65535")
	s.Nat.Postrouting.Append("-s #{pat_bridge_interface_subnet_cidr} ! -d #{pat_bridge_interface_subnet_cidr} -o #{pat_branch_interface_name} -j MASQUERADE")

	s.Filter.Input.Append("-i virbr0 -p udp -m udp --dport 53 -j ACCEPT")
	s.Filter.Input.Append("-i virbr0 -p tcp -m tcp --dport 53 -j ACCEPT")
	s.Filter.Input.Append("-i virbr0 -p udp -m udp --dport 67 -j ACCEPT")
	s.Filter.Input.Append("-i virbr0 -p tcp -m tcp --dport 67 -j ACCEPT")
	s.Filter.Forward.Append("-d #{pat_bridge_interface_subnet_cidr} -i #{pat_branch_interface_name} -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
	s.Filter.Forward.Append("-s #{pat_bridge_interface_subnet_cidr} -i virbr0 -o #{pat_branch_interface_name} -j ACCEPT")
	s.Filter.Forward.Append("-i virbr0 -o virbr0 -j ACCEPT")
	s.Filter.Forward.Append("-o virbr0 -j REJECT --reject-with icmp-port-unreachable")
	s.Filter.Forward.Append("-i virbr0 -j REJECT --reject-with icmp-port-unreachable")
	s.Filter.Output.Append("-o virbr0 -p udp -m udp --dport 68 -j ACCEPT")

	expected := `*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i virbr0 -p udp -m udp --dport 53 -j ACCEPT
-A INPUT -i virbr0 -p tcp -m tcp --dport 53 -j ACCEPT
-A INPUT -i virbr0 -p udp -m udp --dport 67 -j ACCEPT
-A INPUT -i virbr0 -p tcp -m tcp --dport 67 -j ACCEPT
-A FORWARD -d #{pat_bridge_interface_subnet_cidr} -i #{pat_branch_interface_name} -o virbr0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -s #{pat_bridge_interface_subnet_cidr} -i virbr0 -o #{pat_branch_interface_name} -j ACCEPT
-A FORWARD -i virbr0 -o virbr0 -j ACCEPT
-A FORWARD -o virbr0 -j REJECT --reject-with icmp-port-unreachable
-A FORWARD -i virbr0 -j REJECT --reject-with icmp-port-unreachable
-A OUTPUT -o virbr0 -p udp -m udp --dport 68 -j ACCEPT
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s #{pat_bridge_interface_subnet_cidr} -d 224.0.0.0/24 -o #{pat_branch_interface_name} -j RETURN
-A POSTROUTING -s #{pat_bridge_interface_subnet_cidr} -d 255.255.255.255/32 -o #{pat_branch_interface_name} -j RETURN
-A POSTROUTING -s #{pat_bridge_interface_subnet_cidr} ! -d #{pat_bridge_interface_subnet_cidr} -o #{pat_branch_interface_name} -p tcp -j MASQUERADE --to-ports 1024-65535
-A POSTROUTING -s #{pat_bridge_interface_subnet_cidr} ! -d #{pat_bridge_interface_subnet_cidr} -o #{pat_branch_interface_name} -p udp -j MASQUERADE --to-ports 1024-65535
-A POSTROUTING -s #{pat_bridge_interface_subnet_cidr} ! -d #{pat_bridge_interface_subnet_cidr} -o #{pat_branch_interface_name} -j MASQUERADE
COMMIT
*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -o virbr0 -p udp -m udp --dport 68 -j CHECKSUM --checksum-fill
COMMIT
`
	result := s.Serialize()
	if result != expected {
		fmt.Println(result)
		fmt.Println(expected)
		t.Fail()
	}
}
