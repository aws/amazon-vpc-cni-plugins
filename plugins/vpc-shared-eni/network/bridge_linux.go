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
	"fmt"
	"net"

	"github.com/aws/amazon-vpc-cni-plugins/network/ebtables"
	"github.com/aws/amazon-vpc-cni-plugins/network/eni"
	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-shared-eni/config"

	log "github.com/cihub/seelog"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// bridgeNameFormat is the format used for generating bridge names (e.g. "vpcbr1").
	bridgeNameFormat = "%sbr%d"

	// vethLinkNameFormat is the format used for generating veth link names.
	vethLinkNameFormat = "veth%s"

	// tapBridgeName is the name of the bridge connecting TAP interfaces.
	tapBridgeName = "tapbr0"
)

// BridgeBuilder implements NetworkBuilder interface by bridging containers to an ENI on Linux.
type BridgeBuilder struct{}

// FindOrCreateNetwork creates a new container network.
func (nb *BridgeBuilder) FindOrCreateNetwork(nw *Network) error {
	var err error

	bridgeName := fmt.Sprintf(bridgeNameFormat, nw.Name, nw.SharedENI.GetLinkIndex())

	// Find the bridge network namespace. If none is specified, use the host network namespace.
	if nw.BridgeNetNSPath != "" {
		var bridgeNetNS netns.NetNS

		log.Infof("Searching for bridge netns %s.", nw.BridgeNetNSPath)
		bridgeNetNS, err = netns.GetNetNSByName(nw.BridgeNetNSPath)
		if err != nil {
			log.Errorf("Failed to find bridge netns %s: %v.", nw.BridgeNetNSPath, err)
			return err
		}

		// Move the ENI link to the bridge network namespace.
		log.Infof("Moving link %s to netns %s.", nw.SharedENI, nw.BridgeNetNSPath)
		err = nw.SharedENI.SetNetNS(bridgeNetNS)
		if err != nil {
			log.Errorf("Failed to move link: %v.", err)
			return err
		}

		// Connect the ENI to a bridge in the bridge network namespace.
		err = bridgeNetNS.Run(func() error {
			nw.BridgeIndex, err = nb.createBridge(bridgeName, nw.SharedENI, nw.ENIIPAddress)
			return err
		})
	} else {
		// Connect the ENI to a bridge.
		nw.BridgeIndex, err = nb.createBridge(bridgeName, nw.SharedENI, nw.ENIIPAddress)
	}

	if err != nil {
		log.Errorf("Failed to create bridge: %v.", err)
	}

	return err
}

// DeleteNetwork deletes a container network.
func (nb *BridgeBuilder) DeleteNetwork(nw *Network) error {
	bridgeName := fmt.Sprintf(bridgeNameFormat, nw.Name, nw.SharedENI.GetLinkIndex())
	err := nb.deleteBridge(bridgeName, nw.SharedENI)

	if err != nil {
		log.Errorf("Failed to delete bridge: %v.", err)
	}

	return err
}

// FindOrCreateEndpoint connects the ENI to target network namespace using veth pairs.
func (nb *BridgeBuilder) FindOrCreateEndpoint(nw *Network, ep *Endpoint) error {
	// Derive endpoint names.
	vethLinkName := fmt.Sprintf(vethLinkNameFormat, ep.ContainerID)
	vethPeerName := vethLinkName + "-2"

	// Find the target network namespace.
	log.Infof("Searching for netns %s.", ep.NetNSName)
	targetNetNS, err := netns.GetNetNS(ep.NetNSName)
	if err != nil {
		log.Errorf("Failed to find netns %s: %v.", ep.NetNSName, err)
		return err
	}

	// Connect the bridge to the target network namespace with a veth pair.
	err = nb.createVethPair(nw.BridgeIndex, targetNetNS, vethLinkName, vethPeerName)
	if err != nil {
		log.Errorf("Failed to create veth pair: %v.", err)
		return err
	}

	// Setup the target network namespace.
	err = targetNetNS.Run(func() error {
		ep.MACAddress, err = nb.setupTargetNetNS(
			vethPeerName, ep.IfType, ep.TapUserID, ep.IfName, ep.IPAddress, nw.GatewayIPAddress)
		return err
	})
	if err != nil {
		log.Errorf("Failed to setup target netns: %v.", err)
		return err
	}

	// Set MAC DNAT rule for IP datagrams sent to the endpoint IP address to endpoint MAC address.
	err = ebtables.NAT.Append(
		ebtables.PreRouting,
		&ebtables.Rule{
			Protocol: "IPv4",
			In:       nw.SharedENI.GetLinkName(),
			Match: &ebtables.IPv4Match{
				Dst: ep.IPAddress.IP,
			},
			Target: &ebtables.DNATTarget{
				ToDst:  ep.MACAddress,
				Target: ebtables.Accept,
			},
		},
	)

	if err != nil {
		log.Errorf("Failed to append DNAT rule for veth link %s: %v.", vethLinkName, err)
	}

	return nil
}

// DeleteEndpoint deletes an endpoint from a container network.
// Deletion is best-effort; tries to clean up endpoint artifacts as much as possible.
func (nb *BridgeBuilder) DeleteEndpoint(nw *Network, ep *Endpoint) error {
	var returnedErr error

	// Find the target network namespace.
	log.Infof("Searching for netns %s.", ep.NetNSName)
	targetNetNS, err := netns.GetNetNS(ep.NetNSName)
	if err != nil {
		log.Errorf("Failed to find netns %s: %v.", ep.NetNSName, err)
		return err
	}

	// Delete the veth pair from the target netns.
	err = targetNetNS.Run(func() error {
		// Query the container interface MAC address.
		link, err := netlink.LinkByName(ep.IfName)
		if err == nil {
			ep.MACAddress = link.Attrs().HardwareAddr
		}

		// Delete the veth pair.
		return nb.deleteVethPair(ep.IfName)
	})
	if err != nil {
		log.Errorf("Failed to delete veth pair %s: %v.", ep.IfName, err)
		returnedErr = err
	}

	// Delete the MAC DNAT rule for the endpoint.
	err = ebtables.NAT.Delete(
		ebtables.PreRouting,
		&ebtables.Rule{
			Protocol: "IPv4",
			In:       nw.SharedENI.GetLinkName(),
			Match: &ebtables.IPv4Match{
				Dst: ep.IPAddress.IP,
			},
			Target: &ebtables.DNATTarget{
				ToDst:  ep.MACAddress,
				Target: ebtables.Accept,
			},
		},
	)

	if err != nil {
		log.Errorf("Failed to delete DNAT rule for endpoint: %v.", err)
		returnedErr = err
	}

	return returnedErr
}

// createBridge creates a bridge connected to the shared ENI. Returns the bridge interface index.
func (nb *BridgeBuilder) createBridge(
	bridgeName string,
	sharedENI *eni.ENI,
	ipAddress *net.IPNet) (int, error) {

	// Check if the bridge already exists.
	bridge, err := net.InterfaceByName(bridgeName)
	if err == nil {
		log.Infof("Found existing bridge %s.", bridgeName)
		return bridge.Index, nil
	}

	// Create the bridge link.
	la := netlink.NewLinkAttrs()
	la.Name = bridgeName
	la.MTU = vpc.JumboFrameMTU
	bridgeLink := &netlink.Bridge{LinkAttrs: la}
	log.Infof("Creating bridge link %+v.", bridgeLink)
	err = netlink.LinkAdd(bridgeLink)
	if err != nil {
		log.Errorf("Failed to create bridge link: %v.", err)
		return 0, err
	}

	// Remove IP address from ENI link.
	log.Infof("Removing IP address %v from ENI link %s.", ipAddress, sharedENI)
	la = netlink.NewLinkAttrs()
	la.Name = sharedENI.GetLinkName()
	eniLink := &netlink.Dummy{LinkAttrs: la}
	address := &netlink.Addr{IPNet: ipAddress}
	err = netlink.AddrDel(eniLink, address)
	if err != nil {
		log.Errorf("Failed to remove IP address from ENI link %v: %v.", eniLink, err)
		return 0, err
	}

	// Append a MAC DNAT rule to broadcast ARP replies.
	broadcastMACAddr, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	err = ebtables.NAT.Append(
		ebtables.PreRouting,
		&ebtables.Rule{
			Protocol: "ARP",
			In:       sharedENI.GetLinkName(),
			Match: &ebtables.ARPMatch{
				Op: "Reply",
			},
			Target: &ebtables.DNATTarget{
				ToDst:  broadcastMACAddr,
				Target: ebtables.Accept,
			},
		},
	)

	if err != nil {
		log.Errorf("Failed to append DNAT rule for ENI link %s: %v.", sharedENI, err)
		return 0, err
	}

	// Append a MAC SNAT rule for unicast frames egress shared ENI to shared ENI's MAC address.
	err = ebtables.NAT.Append(
		ebtables.PostRouting,
		&ebtables.Rule{
			Out:     sharedENI.GetLinkName(),
			SrcType: "unicast",
			Target: &ebtables.SNATTarget{
				ToSrc:  sharedENI.GetMACAddress(),
				ARP:    true,
				Target: ebtables.Accept,
			},
		},
	)

	if err != nil {
		log.Errorf("Failed to append SNAT rule for ENI link %s: %v.", sharedENI, err)
		return 0, err
	}

	// Set bridge link MTU.
	log.Infof("Setting bridge link %s MTU to %d octets.", bridgeName, vpc.JumboFrameMTU)
	err = netlink.LinkSetMTU(bridgeLink, vpc.JumboFrameMTU)
	if err != nil {
		log.Errorf("Failed to set bridge link MTU: %v.", err)
		return 0, err
	}

	// Set ENI link operational state down.
	err = sharedENI.SetOpState(false)
	if err != nil {
		log.Errorf("Failed to set ENI link %s state: %v.", sharedENI, err)
		return 0, err
	}

	// Set the ENI link MTU.
	// This is necessary in case the ENI was not configured by DHCP.
	log.Infof("Setting ENI link %s MTU to %d octets.", sharedENI, vpc.JumboFrameMTU)
	err = sharedENI.SetLinkMTU(vpc.JumboFrameMTU)
	if err != nil {
		log.Errorf("Failed to set ENI link MTU: %v.", err)
		return 0, err
	}

	// Connect ENI link to the bridge.
	log.Infof("Setting ENI link %s master to %s.", sharedENI, bridgeName)
	la = netlink.NewLinkAttrs()
	la.Name = sharedENI.GetLinkName()
	eniLink = &netlink.Dummy{LinkAttrs: la}
	err = netlink.LinkSetMaster(eniLink, bridgeLink)
	if err != nil {
		log.Errorf("Failed to set ENI link master: %v", err)
		return 0, err
	}

	// Set ENI link operational state up.
	err = sharedENI.SetOpState(true)
	if err != nil {
		log.Errorf("Failed to set ENI link %s state: %v.", sharedENI, err)
		return 0, err
	}

	// Set bridge link operational state up.
	err = netlink.LinkSetUp(bridgeLink)
	if err != nil {
		log.Errorf("Failed to set bridge link state up: %v.", err)
		return 0, err
	}

	// Assign IP address to bridge.
	log.Infof("Assigning IP address %v to bridge link %s.", ipAddress, bridgeName)
	address = &netlink.Addr{IPNet: ipAddress}
	err = netlink.AddrAdd(bridgeLink, address)
	if err != nil {
		log.Errorf("Failed to assign IP address to bridge link %v: %v.", bridgeName, err)
		return 0, err
	}

	// Add default route to subnet gateway via bridge.
	subnet, err := vpc.NewSubnet(vpc.GetSubnetPrefix(ipAddress))
	if err != nil {
		log.Errorf("Failed to parse VPC subnet for %s: %v.", ipAddress, err)
		return 0, err
	}

	route := &netlink.Route{
		Gw:        subnet.Gateways[0],
		LinkIndex: bridgeLink.Attrs().Index,
	}
	log.Infof("Adding default IP route %+v.", route)

	err = netlink.RouteAdd(route)
	if err != nil {
		log.Errorf("Failed to add IP route %+v: %v.", route, err)
		return 0, err
	}

	return bridgeLink.Attrs().Index, nil
}

// deleteBridge deletes the bridge connected to the shared ENI.
func (nb *BridgeBuilder) deleteBridge(
	bridgeName string,
	sharedENI *eni.ENI) error {

	// Delete the MAC DNAT rule that broadcasts ARP replies ingress shared ENI.
	broadcastMACAddr, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")

	err := ebtables.NAT.Delete(
		ebtables.PreRouting,
		&ebtables.Rule{
			Protocol: "ARP",
			In:       sharedENI.GetLinkName(),
			Match: &ebtables.ARPMatch{
				Op: "Reply",
			},
			Target: &ebtables.DNATTarget{
				ToDst:  broadcastMACAddr,
				Target: ebtables.Accept,
			},
		},
	)

	if err != nil {
		log.Errorf("Failed to delete DNAT rule for ENI link %s: %v.", sharedENI, err)
		return err
	}

	// Delete the MAC SNAT rule to shared ENI's MAC address.
	err = ebtables.NAT.Delete(
		ebtables.PostRouting,
		&ebtables.Rule{
			Out:     sharedENI.GetLinkName(),
			SrcType: "unicast",
			Target: &ebtables.SNATTarget{
				ToSrc:  sharedENI.GetMACAddress(),
				ARP:    true,
				Target: ebtables.Accept,
			},
		},
	)

	if err != nil {
		log.Errorf("Failed to delete SNAT rule for ENI link %s: %v.", sharedENI, err)
		return err
	}

	// Delete the bridge.
	la := netlink.NewLinkAttrs()
	la.Name = bridgeName
	bridgeLink := &netlink.Bridge{LinkAttrs: la}
	log.Infof("Deleting bridge link %+v.", bridgeLink)
	err = netlink.LinkDel(bridgeLink)
	if err != nil {
		log.Errorf("Failed to delete bridge %s: %v.", bridgeName, err)
		return err
	}

	return nil
}

// createVethPair creates a veth pair and moves one peer to the target network namespace.
func (nb *BridgeBuilder) createVethPair(
	bridgeIndex int,
	targetNetNS netns.NetNS,
	vethLinkName string,
	vethPeerName string) error {

	// Check if the veth pair already exists.
	_, err := netlink.LinkByName(vethLinkName)
	if err == nil {
		log.Infof("Found existing veth pair  %s.", vethLinkName)
		return nil
	}

	// Create the veth link and connect it to the bridge.
	la := netlink.NewLinkAttrs()
	la.Name = vethLinkName
	la.MasterIndex = bridgeIndex
	la.MTU = vpc.JumboFrameMTU
	vethLink := &netlink.Veth{
		LinkAttrs: la,
		PeerName:  vethPeerName,
	}

	log.Infof("Creating veth pair %+v.", vethLink)
	err = netlink.LinkAdd(vethLink)
	if err != nil {
		log.Errorf("Failed to add veth pair %s: %v.", vethLinkName, err)
		return err
	}

	// Set the veth link operational state up.
	err = netlink.LinkSetUp(vethLink)
	if err != nil {
		log.Errorf("Failed to set veth link %s state up: %v.", vethLinkName, err)
		return err
	}

	// Move the veth link's peer to target network namespace.
	log.Infof("Moving veth link peer %s to target netns.", vethPeerName)
	la = netlink.NewLinkAttrs()
	la.Name = vethPeerName
	vethPeer := &netlink.Dummy{LinkAttrs: la}
	err = netlink.LinkSetNsFd(vethPeer, int(targetNetNS.GetFd()))
	if err != nil {
		log.Errorf("Failed to move veth link peer %s to target netns: %v.", vethPeerName, err)
		return err
	}

	return nil
}

// deleteVethPair deletes the given veth pair.
func (nb *BridgeBuilder) deleteVethPair(vethPeerName string) error {
	la := netlink.NewLinkAttrs()
	la.Name = vethPeerName
	vethLink := &netlink.Veth{LinkAttrs: la}
	log.Infof("Deleting veth pair: %v.", vethPeerName)
	err := netlink.LinkDel(vethLink)
	if err != nil {
		log.Errorf("Failed to delete veth pair %s: %v.", vethPeerName, err)
	}

	return err
}

// setupTargetNetNS configures the target network namespace.
// Returns the MAC address of the container interface.
func (nb *BridgeBuilder) setupTargetNetNS(
	vethPeerName string,
	ifType string,
	tapUserID int,
	ifName string,
	ipAddress *net.IPNet,
	gatewayIPAddress net.IP) (net.HardwareAddr, error) {

	// Check if the container interface already exists.
	link, err := netlink.LinkByName(ifName)
	if err == nil {
		log.Infof("Found existing container interface  %s.", ifName)
		return link.Attrs().HardwareAddr, nil
	}

	switch ifType {
	case config.IfTypeVETH:
		err = nb.setupVethLink(vethPeerName, ifName, ipAddress, gatewayIPAddress)
	case config.IfTypeTAP:
		err = nb.createTAPLink(vethPeerName, ifName, tapUserID)
	}

	if err != nil {
		return nil, err
	}

	// Query the container interface MAC address.
	link, _ = netlink.LinkByName(ifName)
	return link.Attrs().HardwareAddr, err
}

// setupVethLink sets up a veth link in the target network namespace.
func (nb *BridgeBuilder) setupVethLink(
	vethPeerName string,
	ifName string,
	ipAddress *net.IPNet,
	gatewayIPAddress net.IP) error {

	var link netlink.Link

	// Rename the veth link to the requested interface name.
	log.Infof("Renaming link %s to %s.", vethPeerName, ifName)
	la := netlink.NewLinkAttrs()
	la.Name = vethPeerName
	link = &netlink.Dummy{LinkAttrs: la}
	err := netlink.LinkSetName(link, ifName)
	if err != nil {
		log.Errorf("Failed to set veth link %s name: %v.", vethPeerName, err)
		return err
	}

	// Set the link operational state up.
	la = netlink.NewLinkAttrs()
	la.Name = ifName
	link = &netlink.Dummy{LinkAttrs: la}
	err = netlink.LinkSetUp(link)
	if err != nil {
		log.Errorf("Failed to set veth link state up: %v.", err)
		return err
	}

	// Set the ENI IP address and the default gateway if specified.
	if ipAddress != nil {
		// Assign the IP address.
		log.Infof("Assigning IP address %v to link %s.", ipAddress, ifName)
		address := &netlink.Addr{IPNet: ipAddress}
		err = netlink.AddrAdd(link, address)
		if err != nil {
			log.Errorf("Failed to assign IP address to link %v: %v.", ifName, err)
			return err
		}

		// If the gateway IP address was not specified, derive it from the ENI IP address.
		if gatewayIPAddress == nil {
			// Parse VPC subnet.
			subnet, err := vpc.NewSubnet(vpc.GetSubnetPrefix(ipAddress))
			if err != nil {
				log.Errorf("Failed to parse VPC subnet for %s: %v.", ipAddress, err)
				return err
			}

			gatewayIPAddress = subnet.Gateways[0]
		}

		iface, err := net.InterfaceByName(ifName)
		if err != nil {
			log.Errorf("Failed to find link index: %v.", err)
			return err
		}

		// Add default route to the specified gateway via ENI.
		route := &netlink.Route{
			Gw:        gatewayIPAddress,
			LinkIndex: iface.Index,
		}
		log.Infof("Adding default IP route %+v.", route)
		err = netlink.RouteAdd(route)
		if err != nil {
			log.Errorf("Failed to add IP route %+v: %v.", route, err)
			return err
		}
	}

	return nil
}

// createTAPLink creates a TAP link in the target network namespace.
func (nb *BridgeBuilder) createTAPLink(linkName string, tapLinkName string, uid int) error {
	// Create the bridge link.
	la := netlink.NewLinkAttrs()
	la.Name = tapBridgeName
	la.MTU = vpc.JumboFrameMTU
	bridge := &netlink.Bridge{LinkAttrs: la}
	log.Infof("Creating bridge link %+v.", bridge)
	err := netlink.LinkAdd(bridge)
	if err != nil {
		log.Errorf("Failed to create bridge link: %v", err)
		return err
	}

	// Set bridge link MTU.
	err = netlink.LinkSetMTU(bridge, vpc.JumboFrameMTU)
	if err != nil {
		log.Errorf("Failed to set bridge link MTU: %v", err)
		return err
	}

	// Set bridge link operational state up.
	err = netlink.LinkSetUp(bridge)
	if err != nil {
		log.Errorf("Failed to set bridge link state: %v", err)
		return err
	}

	// Connect link to the bridge.
	la = netlink.NewLinkAttrs()
	la.Name = linkName
	link := &netlink.Dummy{LinkAttrs: la}
	err = netlink.LinkSetMaster(link, bridge)
	if err != nil {
		log.Errorf("Failed to set link master: %v", err)
		return err
	}

	// Create the TAP link.
	la = netlink.NewLinkAttrs()
	la.Name = tapLinkName
	la.MasterIndex = bridge.Index
	la.MTU = vpc.JumboFrameMTU
	tapLink := &netlink.Tuntap{
		LinkAttrs: la,
		Mode:      netlink.TUNTAP_MODE_TAP,
		Flags:     netlink.TUNTAP_ONE_QUEUE | netlink.TUNTAP_VNET_HDR,
		Queues:    1,
	}

	log.Infof("Creating TAP link %+v.", tapLink)
	err = netlink.LinkAdd(tapLink)
	if err != nil {
		log.Errorf("Failed to add TAP link: %v", err)
		return err
	}

	// Set TAP link MTU.
	err = netlink.LinkSetMTU(tapLink, vpc.JumboFrameMTU)
	if err != nil {
		log.Errorf("Failed to set TAP link MTU: %v", err)
		return err
	}

	// Set TAP link ownership.
	log.Infof("Setting TAP link owner to uid %d.", uid)
	fd := int(tapLink.Fds[0].Fd())
	err = unix.IoctlSetInt(fd, unix.TUNSETOWNER, uid)
	if err != nil {
		log.Errorf("Failed to set TAP link owner: %v", err)
		return err
	}

	// Set TAP link operational state up.
	err = netlink.LinkSetUp(tapLink)
	if err != nil {
		log.Errorf("Failed to set TAP link state: %v", err)
		return err
	}

	return nil
}
