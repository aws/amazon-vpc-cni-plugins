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
	"encoding/json"
	"fmt"
	"net"

	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"

	"github.com/Microsoft/hcsshim"
	log "github.com/cihub/seelog"
)

const (
	// hnsL2Bridge is the HNS network type used by this plugin on Windows.
	hnsL2Bridge = "l2bridge"

	// hnsNetworkNameFormat is the format used for generating bridge names (e.g. "vpcbr1").
	hnsNetworkNameFormat = "%sbr%s"

	// hnsEndpointNameFormat is the format of the names generated for HNS endpoints.
	hnsEndpointNameFormat = "cid-%s"
)

var (
	// hnsMinVersion is the minimum version of HNS supported by this plugin.
	hnsMinVersion = hcsshim.HNSVersion1803
)

// routePolicy is an HNS route policy.
// This definition really needs to be in Microsoft's hcsshim package.
type routePolicy struct {
	hcsshim.Policy
	DestinationPrefix string `json:"DestinationPrefix,omitempty"`
	NeedEncap         bool   `json:"NeedEncap,omitempty"`
}

// BridgeBuilder implements NetworkBuilder interface by bridging containers to an ENI on Windows.
type BridgeBuilder struct{}

// FindOrCreateNetwork creates a new HNS network.
func (nb *BridgeBuilder) FindOrCreateNetwork(nw *Network) error {
	// Check that the HNS version is supported.
	err := nb.checkHNSVersion()
	if err != nil {
		return err
	}

	// HNS API does not support creating virtual switches in compartments other than the host's.
	if nw.BridgeNetNSName != "" {
		return fmt.Errorf("Bridge must be in host network namespace on Windows")
	}

	// Check if the network already exists.
	networkName := nb.generateHNSNetworkName(nw)
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
	if err == nil {
		log.Infof("Found existing HNS network %s.", networkName)
		return nil
	}

	// Initialize the HNS network.
	hnsNetwork = &hcsshim.HNSNetwork{
		Name:               networkName,
		Type:               hnsL2Bridge,
		NetworkAdapterName: nw.SharedENI.GetLinkName(),

		Subnets: []hcsshim.Subnet{
			{
				AddressPrefix:  vpc.GetSubnetPrefix(nw.ENIIPAddress).String(),
				GatewayAddress: nw.GatewayIPAddress.String(),
			},
		},
	}

	buf, err := json.Marshal(hnsNetwork)
	if err != nil {
		return err
	}
	hnsRequest := string(buf)

	// Create the HNS network.
	log.Infof("Creating HNS network: %+v", hnsRequest)
	hnsResponse, err := hcsshim.HNSNetworkRequest("POST", "", hnsRequest)
	if err != nil {
		log.Errorf("Failed to create HNS network: %v.", err)
		return err
	}

	log.Infof("Received HNS network response: %+v.", hnsResponse)

	return nil
}

// DeleteNetwork deletes an existing HNS network.
func (nb *BridgeBuilder) DeleteNetwork(nw *Network) error {
	// Find the HNS network ID.
	networkName := nb.generateHNSNetworkName(nw)
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
	if err != nil {
		return err
	}

	// Delete the HNS network.
	log.Infof("Deleting HNS network name: %s ID: %s", networkName, hnsNetwork.Id)
	_, err = hcsshim.HNSNetworkRequest("DELETE", hnsNetwork.Id, "")
	if err != nil {
		log.Errorf("Failed to delete HNS network: %v.", err)
	}

	return err
}

// FindOrCreateEndpoint creates a new HNS endpoint in the network.
func (nb *BridgeBuilder) FindOrCreateEndpoint(nw *Network, ep *Endpoint) error {
	// Check if the endpoint already exists.
	endpointName := nb.generateHNSEndpointName(ep)
	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(endpointName)
	if err == nil {
		log.Infof("Found existing HNS endpoint %s.", endpointName)
		return nil
	}

	// Initialize the HNS endpoint.
	hnsEndpoint = &hcsshim.HNSEndpoint{
		Name:               endpointName,
		VirtualNetworkName: nb.generateHNSNetworkName(nw),
		DNSSuffix:          "",
		DNSServerList:      "10.100.0.10",
	}

	// Set the IP address.
	hnsEndpoint.IPAddress = ep.IPAddress.IP
	pl, _ := ep.IPAddress.Mask.Size()
	hnsEndpoint.PrefixLength = uint8(pl)

	// Enable SNAT to primary VPC IP address for destinations outside of VPC subnets.
	err = nb.addEndpointPolicy(hnsEndpoint, hcsshim.OutboundNatPolicy{
		Policy: hcsshim.Policy{Type: hcsshim.OutboundNat},
		VIP:    nw.ENIIPAddress.IP.String(),
		Exceptions: []string{
			vpc.GetSubnetPrefix(nw.ENIIPAddress).String(),
		},
	})
	if err != nil {
		log.Errorf("Failed to add SNAT policy to HNS endpoint: %v.", err)
		return err
	}

	// Encode the endpoint request.
	buf, err := json.Marshal(hnsEndpoint)
	if err != nil {
		return err
	}
	hnsRequest := string(buf)

	// Create the HNS endpoint.
	log.Infof("Creating HNS endpoint: %+v", hnsRequest)
	hnsResponse, err := hcsshim.HNSEndpointRequest("POST", "", hnsRequest)
	if err != nil {
		log.Errorf("Failed to create HNS endpoint: %v.", err)
		return err
	}

	log.Infof("Received HNS endpoint response: %+v.", hnsResponse)

	// Attach the HNS endpoint to container network namespace.
	log.Infof("Attaching HNS endpoint %s to container %s.", hnsResponse.Id, ep.ContainerID)
	err = hcsshim.HotAttachEndpoint(ep.ContainerID, hnsResponse.Id)
	if err != nil {
		log.Errorf("Failed to attach HNS endpoint. Ignoring failure: %v.", err)
	}

	// Return network interface MAC address.
	ep.MACAddress, _ = net.ParseMAC(hnsResponse.MacAddress)

	return nil
}

// DeleteEndpoint deletes an existing HNS endpoint.
func (nb *BridgeBuilder) DeleteEndpoint(nw *Network, ep *Endpoint) error {
	// Find the HNS endpoint ID.
	endpointName := nb.generateHNSEndpointName(ep)
	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(endpointName)
	if err != nil {
		return err
	}

	// Delete the HNS endpoint.
	log.Infof("Deleting HNS endpoint name: %s ID: %s", endpointName, hnsEndpoint.Id)
	_, err = hcsshim.HNSEndpointRequest("DELETE", hnsEndpoint.Id, "")
	if err != nil {
		log.Errorf("Failed to delete HNS endpoint: %v.", err)
	}

	return err
}

// checkHNSVersion returns whether the Windows Host Networking Service version is supported.
func (nb *BridgeBuilder) checkHNSVersion() error {
	hnsGlobals, err := hcsshim.GetHNSGlobals()
	if err != nil {
		return err
	}

	hnsVersion := hnsGlobals.Version
	log.Infof("Running on HNS version: %+v", hnsVersion)

	supported := hnsVersion.Major > hnsMinVersion.Major ||
		(hnsVersion.Major == hnsMinVersion.Major && hnsVersion.Minor >= hnsMinVersion.Minor)

	if !supported {
		return fmt.Errorf("HNS is older than the minimum supported version %v", hnsMinVersion)
	}

	return nil
}

// generateHNSNetworkName generates a deterministic unique name for an HNS network.
func (nb *BridgeBuilder) generateHNSNetworkName(nw *Network) string {
	return fmt.Sprintf(hnsNetworkNameFormat, nw.Name, nw.SharedENI.GetMACAddress().String())
}

// generateHNSEndpointName generates a deterministic unique name for an HNS endpoint.
func (nb *BridgeBuilder) generateHNSEndpointName(ep *Endpoint) string {
	return fmt.Sprintf(hnsEndpointNameFormat, ep.ContainerID)
}

// addEndpointPolicy adds a policy to an HNS endpoint.
func (nb *BridgeBuilder) addEndpointPolicy(ep *hcsshim.HNSEndpoint, policy interface{}) error {
	buf, err := json.Marshal(policy)
	if err != nil {
		log.Errorf("Failed to encode policy: %v.", err)
		return err
	}

	ep.Policies = append(ep.Policies, buf)

	return nil
}
