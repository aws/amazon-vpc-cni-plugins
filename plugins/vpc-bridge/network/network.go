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

package network

import (
	"net"

	"github.com/aws/amazon-vpc-cni-plugins/network/eni"
	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"
)

// Builder knows how to build container networks and connect container network interfaces.
type Builder interface {
	FindOrCreateNetwork(nw *Network) error
	DeleteNetwork(nw *Network) error
	FindOrCreateEndpoint(nw *Network, ep *Endpoint) error
	DeleteEndpoint(nw *Network, ep *Endpoint) error
}

// Network represents a container network.
type Network struct {
	Name                string
	NetworkID           string
	BridgeType          string
	BridgeNetNSPath     string
	BridgeIndex         int
	SharedENI           *eni.ENI
	ENIIPAddresses      []net.IPNet
	GatewayIPAddress    net.IP
	VPCCIDRs            []net.IPNet
	DNSServers          []string
	DNSSuffixSearchList []string
	ServiceCIDR         string
}

// Endpoint represents a container network interface.
type Endpoint struct {
	ContainerID  string
	NetNSName    string
	IfName       string
	IfType       string
	TapUserID    int
	MACAddress   net.HardwareAddr
	IPAddresses  []net.IPNet
	PortMappings []vpc.PortMapping
}
