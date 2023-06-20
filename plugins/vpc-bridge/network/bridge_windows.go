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
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	log "github.com/cihub/seelog"
)

const (
	// hcnSchemaVersionMajor indicates major version number for HCN schema.
	hcnSchemaMajorVersion = 2

	// hcnSchemaVersionMinor indicates minor version number for HCN schema.
	hcnSchemaMinorVersion = 0

	// hnsL2Bridge is the HNS network type used by this plugin on Windows.
	hnsL2Bridge = "l2bridge"

	// hcnNetworkNameFormat is the format used for generating bridge names (e.g. "vpcbr1").
	hcnNetworkNameFormat = "%sbr%s"

	// hcnEndpointNameFormat is the format of the names generated for HCN endpoints.
	hcnEndpointNameFormat = "cid-%s"

	// defaultRoute is the default route in the route table.
	defaultRoute = "0.0.0.0/0"
)

// nsType identifies the namespace type for the containers.
type nsType int

const (
	// infraContainerNS identifies an Infra container NS for networking setup.
	infraContainerNS nsType = iota
	// appContainerNS identifies sharing of infra container NS for networking setup.
	appContainerNS
	// hcnNamespace identifies HCN NS for networking setup.
	hcnNamespace
)

var (
	// hnsMinVersion is the minimum version of HNS supported by this plugin.
	hnsMinVersion = hcsshim.HNSVersion1803
)

// BridgeBuilder implements NetworkBuilder interface by bridging containers to an ENI on Windows.
type BridgeBuilder struct{}

// FindOrCreateNetwork creates a new HCN network.
func (nb *BridgeBuilder) FindOrCreateNetwork(nw *Network) error {
	// Check that the HNS version is supported.
	err := nb.checkHNSVersion()
	if err != nil {
		return err
	}

	// HNS API does not support creating virtual switches in compartments other than the host's.
	if nw.BridgeNetNSPath != "" {
		return fmt.Errorf("bridge must be in host network namespace on Windows")
	}

	// Check if the network already exists.
	networkName := nb.generateHNSNetworkName(nw)
	hcnNetwork, err := hcn.GetNetworkByName(networkName)
	if err == nil {
		log.Infof("Found existing HCN network %s.", networkName)
		nw.NetworkID = hcnNetwork.Id
		return nil
	}

	// Initialize the HCN network.
	hcnNetwork = &hcn.HostComputeNetwork{
		Name: networkName,
		Type: hnsL2Bridge,
		Ipams: []hcn.Ipam{
			{
				Subnets: []hcn.Subnet{
					{
						IpAddressPrefix: vpc.GetSubnetPrefix(&nw.ENIIPAddresses[0]).String(),
						Routes: []hcn.Route{
							{
								NextHop:           nw.GatewayIPAddress.String(),
								DestinationPrefix: defaultRoute,
							},
						},
					},
				},
			},
		},
		SchemaVersion: hcn.SchemaVersion{
			Major: hcnSchemaMajorVersion,
			Minor: hcnSchemaMinorVersion,
		},
	}

	// Create the network policy for the adapter to which the vSwitch binds.
	err = nb.addNetworkPolicy(
		hcnNetwork,
		hcn.NetAdapterName,
		hcn.NetAdapterNameNetworkPolicySetting{
			NetworkAdapterName: nw.SharedENI.GetLinkName(),
		})
	if err != nil {
		return err
	}

	// Create the HCN network.
	log.Infof("Creating HCN network: %+v", hcnNetwork)
	hcnResponse, err := hcnNetwork.Create()
	if err != nil {
		log.Errorf("Failed to create HCN network: %v.", err)
		return err
	}
	log.Infof("Received HCN response: %+v.", hcnResponse)

	nw.NetworkID = hcnResponse.Id
	return nil
}

// DeleteNetwork deletes an existing HCN network.
func (nb *BridgeBuilder) DeleteNetwork(nw *Network) error {
	// Find the HCN network ID.
	networkName := nb.generateHNSNetworkName(nw)
	hcnNetwork, err := hcn.GetNetworkByName(networkName)
	if err != nil {
		return err
	}

	// Delete the HCN network.
	log.Infof("Deleting HCN network name: %s ID: %s", networkName, hcnNetwork.Id)
	err = hcnNetwork.Delete()
	if err != nil {
		log.Errorf("Failed to delete HCN network: %v.", err)
	}

	return err
}

// FindOrCreateEndpoint creates a new HCN endpoint in the network.
func (nb *BridgeBuilder) FindOrCreateEndpoint(nw *Network, ep *Endpoint) error {
	// This plugin does not yet support IPv6, or multiple IPv4 addresses.
	if len(ep.IPAddresses) > 1 || ep.IPAddresses[0].IP.To4() == nil {
		return fmt.Errorf("Only a single IPv4 address per endpoint is supported on Windows")
	}

	// Query the namespace identifier.
	nsType, namespaceIdentifier := nb.getNamespaceIdentifier(ep)

	// Check if the endpoint already exists.
	endpointName := nb.generateHNSEndpointName(ep, namespaceIdentifier)
	hcnEndpoint, err := hcn.GetEndpointByName(endpointName)
	if err == nil {
		log.Infof("Found existing HCN endpoint %s.", endpointName)
		if nsType == infraContainerNS || nsType == hcnNamespace {
			// This is a benign duplicate create call for an existing endpoint.
			// The endpoint was already attached in a previous call. Ignore and return success.
			log.Infof("HCN endpoint %s is already attached to container ID %s.",
				endpointName, ep.ContainerID)
		} else {
			// Attach the existing endpoint to the container's network namespace.
			// Attachment of endpoint to each container would occur only when using HNS V1 APIs.
			err = nb.attachEndpointV1(hcnEndpoint, ep.ContainerID)
		}

		ep.MACAddress, _ = net.ParseMAC(hcnEndpoint.MacAddress)
		return err
	} else {
		if nsType != infraContainerNS && nsType != hcnNamespace {
			// The endpoint referenced in the container netns does not exist.
			log.Errorf("Failed to find endpoint %s for container %s.", endpointName, ep.ContainerID)
			return fmt.Errorf("failed to find endpoint %s: %v", endpointName, err)
		}
	}

	// Initialize the HCN endpoint.
	hcnEndpoint = &hcn.HostComputeEndpoint{
		Name:               endpointName,
		HostComputeNetwork: nw.NetworkID,
		IpConfigurations:   nil,
		Dns: hcn.Dns{
			Search:     nw.DNSSuffixSearchList,
			ServerList: nw.DNSServers,
		},
		SchemaVersion: hcn.SchemaVersion{
			Major: hcnSchemaMajorVersion,
			Minor: hcnSchemaMinorVersion,
		},
	}

	// Set the endpoint IP address.
	pl, _ := ep.IPAddresses[0].Mask.Size()
	hcnEndpoint.IpConfigurations = []hcn.IpConfig{
		{
			IpAddress:    ep.IPAddresses[0].IP.String(),
			PrefixLength: uint8(pl),
		},
	}

	// SNAT endpoint traffic to ENI primary IP address...
	var snatExceptions []string
	if nw.VPCCIDRs == nil {
		// ...except if the destination is in the same subnet as the ENI.
		snatExceptions = []string{vpc.GetSubnetPrefix(&nw.ENIIPAddresses[0]).String()}
	} else {
		// ...or, if known, the same VPC.
		for _, cidr := range nw.VPCCIDRs {
			snatExceptions = append(snatExceptions, cidr.String())
		}
	}
	if nw.ServiceCIDR != "" {
		// ...or the destination is a service endpoint.
		snatExceptions = append(snatExceptions, nw.ServiceCIDR)
	}

	err = nb.addEndpointPolicy(
		hcnEndpoint,
		hcn.OutBoundNAT,
		hcn.OutboundNatPolicySetting{
			// Implicit VIP: nw.ENIIPAddresses[0].IP.String(),
			Exceptions: snatExceptions,
		})
	if err != nil {
		log.Errorf("Failed to add endpoint SNAT policy: %v.", err)
		return err
	}

	// Add the policies for any port mappings applicable to the endpoint.
	for _, portMapEntry := range ep.PortMappings {
		// Determine the protocol number.
		protocol, err := vpc.ProtocolToNumber(portMapEntry.Protocol)
		if err != nil {
			log.Errorf("Failed to parse the protocol: %v.", err)
			return err
		}

		// Create the port mapping policy.
		err = nb.addEndpointPolicy(
			hcnEndpoint,
			hcn.PortMapping,
			hcn.PortMappingPolicySetting{
				Protocol:     protocol,
				InternalPort: uint16(portMapEntry.ContainerPort),
				ExternalPort: uint16(portMapEntry.HostPort),
				Flags:        hcn.NatFlagsLocalRoutedVip,
			})
		if err != nil {
			log.Errorf("Failed to add endpoint port mapping policy: %v.", err)
			return err
		}
	}

	// Route traffic sent to service endpoints to the host. The load balancer running
	// in the host network namespace then forwards traffic to its final destination.
	if nw.ServiceCIDR != "" {
		// Set route policy for service subnet.
		// NextHop is implicitly the host.
		err = nb.addEndpointPolicy(
			hcnEndpoint,
			hcn.SDNRoute,
			hcn.SDNRoutePolicySetting{
				DestinationPrefix: nw.ServiceCIDR,
				NeedEncap:         true,
			})
		if err != nil {
			log.Errorf("Failed to add endpoint route policy for service subnet: %v.", err)
			return err
		}

		// Set route policy for host primary IP address.
		err = nb.addEndpointPolicy(
			hcnEndpoint,
			hcn.SDNRoute,
			hcn.SDNRoutePolicySetting{
				DestinationPrefix: nw.ENIIPAddresses[0].IP.String() + "/32",
				NeedEncap:         true,
			})
		if err != nil {
			log.Errorf("Failed to add endpoint route policy for host: %v.", err)
			return err
		}
	}

	// Create the HCN endpoint.
	log.Infof("Creating HCN endpoint: %+v", hcnEndpoint)
	hcnResponse, err := hcnEndpoint.Create()
	if err != nil {
		log.Errorf("Failed to create HCN endpoint: %v.", err)
		return err
	}

	log.Infof("Received HCN endpoint response: %+v.", hcnResponse)

	// Attach the HCN endpoint to the container's network namespace.
	if nsType == infraContainerNS {
		err = nb.attachEndpointV1(hcnResponse, ep.ContainerID)
	}
	if nsType == hcnNamespace {
		err = nb.attachEndpointV2(hcnResponse, namespaceIdentifier)
	}
	if err != nil {
		// Cleanup the failed endpoint.
		log.Infof("Deleting the failed HCN endpoint %s.", hcnResponse.Id)
		delErr := hcnResponse.Delete()
		if delErr != nil {
			log.Errorf("Failed to delete HCN endpoint: %v.", delErr)
		}

		return err
	}

	// Return network interface MAC address.
	ep.MACAddress, _ = net.ParseMAC(hcnResponse.MacAddress)

	return nil
}

// DeleteEndpoint deletes an existing HCN endpoint.
func (nb *BridgeBuilder) DeleteEndpoint(nw *Network, ep *Endpoint) error {
	// Query the namespace identifier.
	nsType, namespaceIdentifier := nb.getNamespaceIdentifier(ep)

	// Find the HCN endpoint ID.
	endpointName := nb.generateHNSEndpointName(ep, namespaceIdentifier)
	hcnEndpoint, err := hcn.GetEndpointByName(endpointName)
	if err != nil {
		return err
	}

	// Detach the HCN endpoint from the container's network namespace.
	log.Infof("Detaching HCN endpoint %s from container %s netns.", hcnEndpoint.Id, ep.ContainerID)
	if nsType == hcnNamespace {
		// Detach the HCN endpoint from the namespace, if we can.
		// HCN Namespace and HCN Endpoint have a 1-1 relationship, therefore,
		// even if detachment of endpoint from namespace fails, we can still proceed to delete it.
		err = hcn.RemoveNamespaceEndpoint(namespaceIdentifier, hcnEndpoint.Id)
		if err != nil {
			log.Errorf("Failed to detach endpoint, ignoring: %v", err)
		}
	} else {
		err = hcsshim.HotDetachEndpoint(ep.ContainerID, hcnEndpoint.Id)
		if err != nil && err != hcsshim.ErrComputeSystemDoesNotExist {
			return err
		}

		// The rest of the delete logic applies to infrastructure container only.
		if nsType == appContainerNS {
			// For non-infra containers, the network must not be deleted.
			return nil
		}
	}

	// Delete the HCN endpoint.
	log.Infof("Deleting HCN endpoint name: %s ID: %s", endpointName, hcnEndpoint.Id)
	err = hcnEndpoint.Delete()
	if err != nil {
		log.Errorf("Failed to delete HCN endpoint: %v.", err)
	}

	return err
}

// attachEndpointV1 attaches an HCN endpoint to a container's network namespace using HNS V1 APIs.
func (nb *BridgeBuilder) attachEndpointV1(ep *hcn.HostComputeEndpoint, containerID string) error {
	log.Infof("Attaching HCN endpoint %s to container %s.", ep.Id, containerID)
	err := hcsshim.HotAttachEndpoint(containerID, ep.Id)
	if err != nil {
		// Attach can fail if the container is no longer running and/or its network namespace
		// has been cleaned up.
		log.Errorf("Failed to attach HCN endpoint %s: %v.", ep.Id, err)
	}

	return err
}

// attachEndpointV2 attaches an HCN endpoint to a network namespace using HNS V2 APIs.
func (nb *BridgeBuilder) attachEndpointV2(ep *hcn.HostComputeEndpoint, netNSName string) error {
	log.Infof("Adding HCN endpoint %s to ns %s.", ep.Id, netNSName)

	// Check if endpoint is already in target namespace.
	nsEndpoints, err := hcn.GetNamespaceEndpointIds(netNSName)
	if err != nil {
		log.Errorf("Failed to get endpoints from namespace %s: %v.", netNSName, err)
		return err
	}
	for _, endpointID := range nsEndpoints {
		if ep.Id == endpointID {
			log.Infof("HCN endpoint %s is already in ns %s.", endpointID, netNSName)
			return nil
		}
	}

	// Add the endpoint to the target namespace.
	err = hcn.AddNamespaceEndpoint(netNSName, ep.Id)
	if err != nil {
		log.Errorf("Failed to attach HCN endpoint %s: %v.", ep.Id, err)
	}

	return err
}

// addNetworkPolicy adds a policy to an HCN network.
func (nb *BridgeBuilder) addNetworkPolicy(
	nw *hcn.HostComputeNetwork,
	policyType hcn.NetworkPolicyType,
	policySettings interface{}) error {
	policySettingsBytes, err := json.Marshal(policySettings)
	if err != nil {
		log.Errorf("Failed to encode network policy settings: %v.", err)
	}

	networkPolicy := hcn.NetworkPolicy{
		Type:     policyType,
		Settings: policySettingsBytes,
	}

	// Add the network policy to the existing policies.
	nw.Policies = append(nw.Policies, networkPolicy)

	return nil
}

// addEndpointPolicy adds a policy to an HCN endpoint.
func (nb *BridgeBuilder) addEndpointPolicy(
	ep *hcn.HostComputeEndpoint,
	policyType hcn.EndpointPolicyType,
	policySettings interface{}) error {
	policySettingsBytes, err := json.Marshal(policySettings)
	if err != nil {
		log.Errorf("Failed to encode endpoint policy settings: %v.", err)
	}

	endpointPolicy := hcn.EndpointPolicy{
		Type:     policyType,
		Settings: policySettingsBytes,
	}

	// Add the network policy to the existing policies.
	ep.Policies = append(ep.Policies, endpointPolicy)

	return nil
}

// getNamespaceIdentifier identifies the namespace type and returns the appropriate identifier.
func (nb *BridgeBuilder) getNamespaceIdentifier(ep *Endpoint) (nsType, string) {
	// Orchestrators like Kubernetes and ECS group a set of containers into deployment units called
	// pods or tasks. The orchestrator agent injects a special container called infrastructure
	// (a.k.a. pause) container into each group to create and share namespaces with the other
	// containers in the same group.
	//
	// Normally, the CNI plugin is called only once, for the infrastructure container. It does not
	// need to know about infrastructure containers and is not even aware of the other containers
	// in the group. However, on older versions of Kubernetes and Windows (pre-1809), CNI plugin is
	// called for each container in the pod separately so that the plugin can attach the endpoint
	// to each container. The logic below is necessary to detect infrastructure containers and
	// maintain compatibility with those older versions.

	const containerPrefix string = "container:"
	var netNSType nsType
	var namespaceIdentifier string

	if ep.NetNSName == "none" || ep.NetNSName == "" {
		// This is the first, i.e. infrastructure, container in the group.
		// The namespace identifier for such containers would be their container ID.
		netNSType = infraContainerNS
		namespaceIdentifier = ep.ContainerID
	} else if strings.HasPrefix(ep.NetNSName, containerPrefix) {
		// This is a workload container sharing the netns of a previously created infra container.
		// The namespace identifier for such containers would be the infra container's ID.
		netNSType = appContainerNS
		namespaceIdentifier = strings.TrimPrefix(ep.NetNSName, containerPrefix)
		log.Infof("Container %s shares netns of container %s.", ep.ContainerID, namespaceIdentifier)
	} else {
		// This plugin invocation does not need an infra container and uses an existing HCN Namespace.
		// The namespace identifier would be the HCN Namespace id.
		netNSType = hcnNamespace
		namespaceIdentifier = ep.NetNSName
		log.Infof("Container %s is in network namespace %s.", ep.ContainerID, namespaceIdentifier)
	}

	return netNSType, namespaceIdentifier
}

// checkHNSVersion returns whether the Windows Host Networking Service version is supported.
func (nb *BridgeBuilder) checkHNSVersion() error {
	// Check if the V2 APIs are supported.
	err := hcn.V2ApiSupported()
	if err != nil {
		return err
	}

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

// generateHNSNetworkName generates a deterministic unique name for an HCN network.
func (nb *BridgeBuilder) generateHNSNetworkName(nw *Network) string {
	// Use the MAC address of the shared ENI as the deterministic unique identifier.
	id := strings.Replace(nw.SharedENI.GetMACAddress().String(), ":", "", -1)
	return fmt.Sprintf(hcnNetworkNameFormat, nw.Name, id)
}

// generateHNSEndpointName generates a deterministic unique name for an HCN endpoint.
func (nb *BridgeBuilder) generateHNSEndpointName(ep *Endpoint, id string) string {
	// Use the given optional identifier or the container ID itself as the unique identifier.
	if id == "" {
		id = ep.ContainerID
	}

	return fmt.Sprintf(hcnEndpointNameFormat, id)
}
