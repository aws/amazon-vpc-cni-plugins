// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package network

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	log "github.com/cihub/seelog"
)

const (
	// hnsNetworkNameFormat is the format of the HNS network name.
	hnsNetworkNameFormat = "%sbr%s"
	// hnsEndpointNameFormat is the format of the HNS Endpoint name.
	hnsEndpointNameFormat = "%s-ep-%s"
	// hnsTransparentNetworkType is the Type of the HNS Network created by the plugin.
	hnsTransparentNetworkType = "Transparent"
	// containerPrefix is the prefix in netns for non-infra containers.
	containerPrefix = "container:"
	// vNICNameFormat is the name format of vNIC created by Windows.
	vNICNameFormat = "vEthernet (%s)"
	// netshDisableInterface is the netsh command to disable a network interface.
	netshDisableInterface = "netsh interface set interface name=\"%s\" admin=disabled"
)

// NSType identifies the namespace type for the containers.
type NSType int

const (
	// infraContainerNS identifies an Infra container NS for networking setup.
	infraContainerNS NSType = iota
	// nonInfraContainerNS identifies sharing of infra container NS for networking setup.
	nonInfraContainerNS
	// hcsNamespace identifies HCS NS for networking setup.
	hcsNamespace
)

var (
	// hnsMinVersion is the minimum version of HNS supported by this plugin.
	hnsMinVersion = hcsshim.HNSVersion1803
)

// NetBuilder implements the Builder interface by moving an eni into a container namespace for Windows.
type NetBuilder struct{}

// FindOrCreateNetwork creates a new HNS network.
func (nb *NetBuilder) FindOrCreateNetwork(nw *Network) error {
	// Check that the HNS version is supported.
	err := nb.checkHNSVersion()
	if err != nil {
		return err
	}

	nw.Name = nb.generateHNSNetworkName(nw)
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(nw.Name)
	if err == nil {
		log.Infof("Found existing HNS network %s.", nw.Name)
		return nil
	}

	// If existing network flag is enabled, many of the parameters of netConfig become optional.
	// This can potentially lead to failure in network creation.
	// Therefore, return error at this point.
	if nw.UseExisting {
		log.Errorf("Failed to find existing network: %s.", nw.Name)
		return fmt.Errorf("failed to find existing network %s", nw.Name)
	}

	// Find the ENI link.
	err = nw.ENI.AttachToLink()
	if err != nil {
		log.Errorf("Failed to find ENI link: %v.", err)
		return err
	}

	// Initialize the HNS network.
	hnsNetwork = &hcsshim.HNSNetwork{
		Name:               nw.Name,
		Type:               hnsTransparentNetworkType,
		NetworkAdapterName: nw.ENI.GetLinkName(),

		Subnets: []hcsshim.Subnet{
			{
				AddressPrefix: vpc.GetSubnetPrefix(&nw.IPAddresses[0]).String(),
			},
		},
	}

	// Gateway IP addresses are optional, therefore, if they are available then add the first one.
	if len(nw.GatewayIPAddresses) != 0 {
		hnsNetwork.Subnets[0].GatewayAddress = nw.GatewayIPAddresses[0].String()
	}

	// Create the HNS network.
	log.Infof("Creating HNS network: %+v", hnsNetwork)
	hnsResponse, err := hnsNetwork.Create()
	if err != nil {
		log.Errorf("Failed to create HNS network: %v.", err)
		return err
	}

	log.Infof("Received HNS network response: %+v.", hnsResponse)

	// For the new network, disable the vNIC in the host compartment.
	mgmtIface := fmt.Sprintf(vNICNameFormat, nw.ENI.GetLinkName())
	err = nb.disableInterface(mgmtIface)
	if err != nil {
		// This is a fatal error as the management vNIC must be disabled.
		_ = nb.DeleteNetwork(nw)
		return err
	}

	return nil
}

// DeleteNetwork deletes an existing HNS network.
func (nb *NetBuilder) DeleteNetwork(nw *Network) error {
	// Find the HNS network.
	hnsNetwork, err := hcsshim.GetHNSNetworkByName(nw.Name)
	if err != nil {
		return err
	}

	// Delete the HNS network.
	log.Infof("Deleting HNS network name: %s ID: %s", nw.Name, hnsNetwork.Id)
	_, err = hnsNetwork.Delete()
	if err != nil {
		log.Errorf("Failed to delete HNS network: %v.", err)
	}

	return err
}

// FindOrCreateEndpoint creates a new HNS endpoint in the network.
func (nb *NetBuilder) FindOrCreateEndpoint(nw *Network, ep *Endpoint) error {
	// Query the namespace identifier.
	nsType, namespaceIdentifier := nb.getNamespaceIdentifier(ep)

	// Check if the endpoint already exists.
	endpointName := nb.generateHNSEndpointName(nw.Name, namespaceIdentifier)
	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(endpointName)
	if err == nil {
		log.Infof("Found existing HNS endpoint %s.", endpointName)
		if nsType == infraContainerNS || nsType == hcsNamespace {
			// This is a benign duplicate create call for an existing endpoint.
			// The endpoint was already attached in a previous call. Ignore and return success.
			log.Infof("HNS endpoint %s is already attached to container ID %s.",
				endpointName, ep.ContainerID)
		} else {
			// Attach the existing endpoint to the container's network namespace.
			// Attachment of endpoint to each container would occur only when using HNS V1 APIs.
			err = nb.attachEndpointV1(hnsEndpoint, ep.ContainerID)
		}

		ep.MACAddress, ep.IPAddresses, nw.GatewayIPAddresses =
			nb.parseEndpointFieldsFromResponse(hnsEndpoint)
		return err
	} else {
		if nsType != infraContainerNS && nsType != hcsNamespace {
			// The endpoint referenced in the container netns does not exist.
			log.Errorf("Failed to find endpoint %s for container %s.", endpointName, ep.ContainerID)
			return fmt.Errorf("failed to find endpoint %s: %v", endpointName, err)
		}
	}

	// Initialize the HNS endpoint.
	hnsEndpoint = &hcsshim.HNSEndpoint{
		Name:               endpointName,
		VirtualNetworkName: nw.Name,
		DNSSuffix:          strings.Join(nw.DNSSuffixSearchList, ","),
		DNSServerList:      strings.Join(nw.DNSServers, ","),
	}

	if ep.MACAddress != nil {
		hnsEndpoint.MacAddress = ep.MACAddress.String()
	}
	if len(ep.IPAddresses) != 0 {
		hnsEndpoint.IPAddress = ep.IPAddresses[0].IP
		pl, _ := ep.IPAddresses[0].Mask.Size()
		hnsEndpoint.PrefixLength = uint8(pl)
	}

	// Create the HNS endpoint.
	log.Infof("Creating HNS endpoint: %+v", hnsEndpoint)
	hnsResponse, err := hnsEndpoint.Create()
	if err != nil {
		log.Errorf("Failed to create HNS endpoint: %v.", err)
		return err
	}

	log.Infof("Received HNS endpoint response: %+v.", hnsResponse)

	// Attach the HNS endpoint to the container's network namespace.
	if nsType == infraContainerNS {
		err = nb.attachEndpointV1(hnsResponse, ep.ContainerID)
	}
	if nsType == hcsNamespace {
		err = nb.attachEndpointV2(hnsResponse, namespaceIdentifier)
	}
	if err != nil {
		// Cleanup the failed endpoint.
		log.Infof("Deleting the failed HNS endpoint %s.", hnsResponse.Id)
		_, delErr := hnsResponse.Delete()
		if delErr != nil {
			log.Errorf("Failed to delete HNS endpoint: %v.", delErr)
		}

		return err
	}

	// Return network interface MAC address, IP Address and Gateway.
	ep.MACAddress, ep.IPAddresses, nw.GatewayIPAddresses =
		nb.parseEndpointFieldsFromResponse(hnsResponse)
	return nil
}

// DeleteEndpoint deletes an existing HNS endpoint.
func (nb *NetBuilder) DeleteEndpoint(nw *Network, ep *Endpoint) error {
	// Generate network name here as endpoint name is dependent upon network name.
	nw.Name = nb.generateHNSNetworkName(nw)
	// Query the namespace identifier.
	nsType, namespaceIdentifier := nb.getNamespaceIdentifier(ep)

	// Find the HNS endpoint ID.
	endpointName := nb.generateHNSEndpointName(nw.Name, namespaceIdentifier)
	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(endpointName)
	if err != nil {
		return err
	}

	// Detach the HNS endpoint from the container's network namespace.
	log.Infof("Detaching HNS endpoint %s from container %s netns.", hnsEndpoint.Id, ep.ContainerID)
	if nsType == hcsNamespace {
		// Detach the HNS endpoint from the namespace, if we can.
		// HCN Namespace and HNS Endpoint have a 1-1 relationship, therefore,
		// even if detachment of endpoint from namespace fails, we can still proceed to delete it.
		err = hcn.RemoveNamespaceEndpoint(namespaceIdentifier, hnsEndpoint.Id)
		if err != nil {
			log.Errorf("Failed to detach endpoint, ignoring: %v", err)
		}
	} else {
		err = hcsshim.HotDetachEndpoint(ep.ContainerID, hnsEndpoint.Id)
		if err != nil && err != hcsshim.ErrComputeSystemDoesNotExist {
			return err
		}

		// The rest of the delete logic applies to infrastructure container only.
		if nsType == nonInfraContainerNS {
			// For non-infra containers, the network must not be deleted.
			nw.UseExisting = true
			return nil
		}
	}

	// Delete the HNS endpoint.
	log.Infof("Deleting HNS endpoint name: %s ID: %s", endpointName, hnsEndpoint.Id)
	_, err = hnsEndpoint.Delete()
	if err != nil {
		log.Errorf("Failed to delete HNS endpoint: %v.", err)
	}

	return err
}

// attachEndpointV1 attaches an HNS endpoint to a container's network namespace using HNS V1 APIs.
func (nb *NetBuilder) attachEndpointV1(ep *hcsshim.HNSEndpoint, containerID string) error {
	log.Infof("Attaching HNS endpoint %s to container %s.", ep.Id, containerID)
	err := hcsshim.HotAttachEndpoint(containerID, ep.Id)
	if err != nil {
		// Attach can fail if the container is no longer running and/or its network namespace
		// has been cleaned up.
		log.Errorf("Failed to attach HNS endpoint %s: %v.", ep.Id, err)
	}

	return err
}

// attachEndpointV2 attaches an HNS endpoint to a network namespace using HNS V2 APIs.
func (nb *NetBuilder) attachEndpointV2(ep *hcsshim.HNSEndpoint, netNSName string) error {
	log.Infof("Adding HNS endpoint %s to ns %s.", ep.Id, netNSName)

	// Check if endpoint is already in target namespace.
	nsEndpoints, err := hcn.GetNamespaceEndpointIds(netNSName)
	if err != nil {
		log.Errorf("Failed to get endpoints from namespace %s: %v.", netNSName, err)
		return err
	}
	for _, endpointID := range nsEndpoints {
		if ep.Id == endpointID {
			log.Infof("HNS endpoint %s is already in ns %s.", endpointID, netNSName)
			return nil
		}
	}

	// Add the endpoint to the target namespace.
	err = hcn.AddNamespaceEndpoint(netNSName, ep.Id)
	if err != nil {
		log.Errorf("Failed to attach HNS endpoint %s: %v.", ep.Id, err)
	}

	return err
}

// getNamespaceIdentifier identifies the namespace type and returns the appropriate identifier.
func (nb *NetBuilder) getNamespaceIdentifier(ep *Endpoint) (NSType, string) {
	var netNSType NSType
	var namespaceIdentifier string

	if ep.NetNSName == "" || ep.NetNSName == "none" {
		// This is the first, i.e. infrastructure, container in the group.
		// The namespace identifier for such containers would be their container ID.
		netNSType = infraContainerNS
		namespaceIdentifier = ep.ContainerID
	} else if strings.HasPrefix(ep.NetNSName, containerPrefix) {
		// This is a workload container sharing the netns of a previously created infra container.
		// The namespace identifier for such containers would be the infra container's ID.
		netNSType = nonInfraContainerNS
		namespaceIdentifier = strings.TrimPrefix(ep.NetNSName, containerPrefix)
		log.Infof("Container %s shares netns of container %s.", ep.ContainerID, namespaceIdentifier)
	} else {
		// This plugin invocation does not need an infra container and uses an existing HCN Namespace.
		// The namespace identifier would be the HCN Namespace id.
		netNSType = hcsNamespace
		namespaceIdentifier = ep.NetNSName
	}

	return netNSType, namespaceIdentifier
}

// checkHNSVersion returns whether the Windows Host Networking Service version is supported.
func (nb *NetBuilder) checkHNSVersion() error {
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
func (nb *NetBuilder) generateHNSNetworkName(nw *Network) string {
	if nw.UseExisting {
		return nw.Name
	}

	// Unique identifier for the network would be of format "task-br-<eni mac address>".
	id := strings.Replace(nw.ENI.GetMACAddress().String(), ":", "", -1)
	return fmt.Sprintf(hnsNetworkNameFormat, nw.Name, id)
}

// generateHNSEndpointName generates a deterministic unique name for the HNS Endpoint.
func (nb *NetBuilder) generateHNSEndpointName(networkName string, identifier string) string {
	return fmt.Sprintf(hnsEndpointNameFormat, networkName, identifier)
}

// disableInterface disables the network interface with the provided name.
func (nb *NetBuilder) disableInterface(adapterName string) error {
	// Check if the interface exists.
	iface, err := net.InterfaceByName(adapterName)
	if err != nil {
		return err
	}

	// Check if the interface is enabled.
	isInterfaceEnabled := strings.EqualFold(strings.Split(iface.Flags.String(), "|")[0], "up")
	if isInterfaceEnabled {
		// Disable the interface using netsh.
		log.Infof("Disabling management vNIC %s in the host namespace.", adapterName)
		commandString := fmt.Sprintf(netshDisableInterface, adapterName)
		cmd := exec.Command("cmd", "/C", commandString)

		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}

// parseEndpointFieldsFromResponse parses and returns the MAC address, IP Address and Gateway address from HNS Endpoint response.
func (nb *NetBuilder) parseEndpointFieldsFromResponse(
	hnsResponse *hcsshim.HNSEndpoint) (net.HardwareAddr, []net.IPNet, []net.IP) {
	mac, _ := net.ParseMAC(hnsResponse.MacAddress)
	ipAddresses := []net.IPNet{
		{
			IP:   hnsResponse.IPAddress,
			Mask: net.CIDRMask(int(hnsResponse.PrefixLength), 32),
		},
	}
	gatewayAddresses := []net.IP{net.ParseIP(hnsResponse.GatewayAddress)}

	return mac, ipAddresses, gatewayAddresses
}
