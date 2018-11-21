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
	"net"

	"github.com/aws/amazon-vpc-cni-plugins/network/eni"
)

// NetworkBuilder knows how to build container networks and connect container network interfaces.
type NetworkBuilder interface {
	FindOrCreateNetwork(nw *Network) error
	DeleteNetwork(nw *Network) error
	FindOrCreateEndpoint(nw *Network, ep *Endpoint) error
	DeleteEndpoint(nw *Network, ep *Endpoint) error
}

// Network represents a container network.
type Network struct {
	Name             string
	BridgeNetNSPath  string
	BridgeIndex      int
	SharedENI        *eni.ENI
	ENIIPAddress     *net.IPNet
	GatewayIPAddress net.IP
	DNSServers       []string
	DNSSuffix        string
	ServiceSubnet    string
}

// Endpoint represents a container network interface.
type Endpoint struct {
	ContainerID string
	NetNSName   string
	IfName      string
	MACAddress  net.HardwareAddr
	IPAddress   *net.IPNet
}
