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
	"os"

	"github.com/aws/amazon-vpc-cni-plugins/network/ebtables"
	"github.com/aws/amazon-vpc-cni-plugins/network/eni"
	"github.com/aws/amazon-vpc-cni-plugins/network/ipcfg"
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

	// dummyNameFormat is the format used for generating dummy link names for a bridge.
	dummyNameFormat = "%sdummy"

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
			nw.BridgeIndex, err = nb.createBridge(
				bridgeName, nw.BridgeType, nw.SharedENI, nw.ENIIPAddresses)
			return err
		})
	} else {
		// Connect the ENI to a bridge.
		nw.BridgeIndex, err = nb.createBridge(
			bridgeName, nw.BridgeType, nw.SharedENI, nw.ENIIPAddresses)
	}

	if err != nil {
		log.Errorf("Failed to create bridge: %v.", err)
	}

	return err
}

// DeleteNetwork deletes a container network.
func (nb *BridgeBuilder) DeleteNetwork(nw *Network) error {
	bridgeName := fmt.Sprintf(bridgeNameFormat, nw.Name, nw.SharedENI.GetLinkIndex())

	err := nb.deleteBridge(bridgeName, nw.BridgeType, nw.SharedENI)

	if err != nil {
		log.Errorf("Failed to delete bridge: %v.", err)
	}

	return err
}

// FindOrCreateEndpoint connects the ENI to target network namespace using veth pairs.
func (nb *BridgeBuilder) FindOrCreateEndpoint(nw *Network, ep *Endpoint) error {
	// Derive endpoint names.
	cid := ep.ContainerID
	if len(cid) > 8 {
		cid = cid[:8]
	}
	vethLinkName := fmt.Sprintf(vethLinkNameFormat, cid)
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
		log.Errorf("Failed to create veth pair %s: %v.", vethLinkName, err)
		return err
	}

	var epIPAddresses []net.IPNet
	var gatewayIPv4Address net.IP
	var gatewayIPv6Address net.IP
	var gatewayIPAddresses []net.IP
	var gatewayMACAddress net.HardwareAddr

	if nw.BridgeType == config.BridgeTypeL3 {
		// Configure the endpoint to relay the default gateway traffic to the on-link bridge.
		bridgeLink, err := netlink.LinkByIndex(nw.BridgeIndex)
		if err == nil {
			gatewayMACAddress = bridgeLink.Attrs().HardwareAddr
		}

		for _, ipAddr := range ep.IPAddresses {
			// Route ingress traffic for this IP address to the bridge.
			dst := ipAddr
			_, maskSize := dst.Mask.Size()
			dst.Mask = net.CIDRMask(maskSize, maskSize)

			route := &netlink.Route{
				LinkIndex: nw.BridgeIndex,
				Scope:     netlink.SCOPE_LINK,
				Dst:       &dst,
			}

			log.Infof("Adding IP route %+v to bridge.", route)
			err = netlink.RouteAdd(route)
			if err != nil && !os.IsExist(err) {
				log.Errorf("Failed to add IP route %+v: %v.", route, err)
				return err
			}

			// The endpoint IP addresses and default gateways are set differently based on the
			// address family.
			if ipAddr.IP.To4() != nil {
				// Assign the endpoint IPv4 address as-is with the actual subnet prefix length.
				epIPAddresses = append(epIPAddresses, ipAddr)

				// For IPv4, the actual VPC subnet default gateway is used as the default gateway.
				// If a gateway address was not specified, derive it from the endpoint's IP address.
				if gatewayIPv4Address == nil {
					if nw.GatewayIPAddress == nil {
						subnet, _ := vpc.NewSubnet(vpc.GetSubnetPrefix(&ipAddr))
						gatewayIPv4Address = subnet.Gateways[0]
					} else {
						gatewayIPv4Address = nw.GatewayIPAddress
					}
					gatewayIPAddresses = append(gatewayIPAddresses, gatewayIPv4Address)
				}
			} else {
				// Set the endpoint IPv6 address prefix length to address size. This essentially
				// disables neighbor discovery and forces the endpoint to send all egress traffic
				// to the default gateway.
				addr := ipAddr
				_, maskSize := addr.Mask.Size()
				addr.Mask = net.CIDRMask(maskSize, maskSize)
				epIPAddresses = append(epIPAddresses, addr)

				// For IPv6, the link-local address of the bridge is used as the default gateway.
				if gatewayIPv6Address == nil {
					addrs, _ := netlink.AddrList(bridgeLink, netlink.FAMILY_V6)
					for _, addr := range addrs {
						if netlink.Scope(addr.Scope) == netlink.SCOPE_LINK {
							gatewayIPv6Address = addr.IP
						}
					}
					gatewayIPAddresses = append(gatewayIPAddresses, gatewayIPv6Address)
				}
			}
		}
	}

	// Setup the target network namespace.
	err = targetNetNS.Run(func() error {
		ep.MACAddress, err = nb.setupTargetNetNS(
			vethPeerName, ep.IfType, ep.TapUserID, ep.IfName, epIPAddresses,
			gatewayIPAddresses, gatewayMACAddress)
		return err
	})
	if err != nil {
		log.Errorf("Failed to setup target netns: %v.", err)
		return err
	}

	if nw.BridgeType == config.BridgeTypeL2 {
		// Set MAC DNAT rule for translating ingress IP datagrams arriving on the shared ENI
		// sent to the endpoint IP address to endpoint MAC address.
		err = ebtables.NAT.Append(
			ebtables.PreRouting,
			&ebtables.Rule{
				Protocol: "IPv4",
				In:       nw.SharedENI.GetLinkName(),
				Match: &ebtables.IPv4Match{
					Dst: ep.IPAddresses[0].IP,
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

	for _, ipAddr := range ep.IPAddresses {
		// Delete bridge layer2 configuration.
		if nw.BridgeType == config.BridgeTypeL2 {
			// Delete the MAC DNAT rule for the endpoint.
			err = ebtables.NAT.Delete(
				ebtables.PreRouting,
				&ebtables.Rule{
					Protocol: "IPv4",
					In:       nw.SharedENI.GetLinkName(),
					Match: &ebtables.IPv4Match{
						Dst: ipAddr.IP,
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
		}

		// Delete the route for ingress traffic for the endpoint to the bridge.
		route := &netlink.Route{
			LinkIndex: nw.BridgeIndex,
			Scope:     netlink.SCOPE_LINK,
			Dst:       &ipAddr,
		}

		_, maskSize := route.Dst.Mask.Size()
		route.Dst.Mask = net.CIDRMask(maskSize, maskSize)

		log.Infof("Deleting IP route %+v from bridge.", route)
		err = netlink.RouteDel(route)
		if err != nil && !os.IsNotExist(err) {
			log.Errorf("Failed to delete IP route %+v: %v.", route, err)
			return err
		}
	}

	return returnedErr
}

// createBridge creates a bridge connected to the shared ENI. Returns the bridge interface index.
func (nb *BridgeBuilder) createBridge(
	bridgeName string,
	bridgeType string,
	sharedENI *eni.ENI,
	ipAddresses []net.IPNet) (int, error) {

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

	// If anything fails during setup, clean up the bridge so that the next call starts clean.
	defer func() {
		if err != nil {
			log.Infof("Cleaning up bridge on error: %v.", err)
			cleanupErr := nb.deleteBridge(bridgeName, bridgeType, sharedENI)
			if cleanupErr != nil {
				log.Errorf("Failed to cleanup bridge: %v.", cleanupErr)
			}
		}
	}()

	// Connect a dummy link to the bridge.
	// Bridge inherits the smallest MTU of links connected to its ports.
	dummyName := fmt.Sprintf(dummyNameFormat, bridgeName)
	la = netlink.NewLinkAttrs()
	la.Name = dummyName
	la.MTU = vpc.JumboFrameMTU
	la.MasterIndex = bridgeLink.Attrs().Index
	dummyLink := &netlink.Dummy{LinkAttrs: la}
	log.Infof("Creating dummy link %+v.", dummyLink)
	err = netlink.LinkAdd(dummyLink)
	if err != nil {
		log.Errorf("Failed to create dummy link: %v.", err)
		return 0, err
	}

	// Set dummy link operational state up.
	err = netlink.LinkSetUp(dummyLink)
	if err != nil {
		log.Errorf("Failed to set dummy link state up: %v.", err)
		return 0, err
	}

	// Set bridge MAC address to dummy's MAC address.
	// Bridge by default inherits the smallest of the MAC addresses of interfaces (veth in this case) connected
	// to its ports. Explicitly setting a static address prevents the bridge from dynamically changing its address
	// as interfaces join and leave the bridge.
	link, err := netlink.LinkByName(dummyName)
	if err != nil {
		log.Errorf("Failed to query dummy link: %v.", err)
		return 0, err
	}
	err = netlink.LinkSetHardwareAddr(bridgeLink, link.Attrs().HardwareAddr)
	if err != nil {
		log.Errorf("Failed to set bridge link MAC address: %v.", err)
		return 0, err
	}

	// Setup bridge layer2 configuration.
	if bridgeType == config.BridgeTypeL2 {
		// Remove IP address from shared ENI link.
		ipAddress := &ipAddresses[0]
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
	}

	// Set bridge link operational state up.
	err = netlink.LinkSetUp(bridgeLink)
	if err != nil {
		log.Errorf("Failed to set bridge link state up: %v.", err)
		return 0, err
	}

	if bridgeType == config.BridgeTypeL2 {
		// In layer2 configuration, the bridge inherits shared ENI's IP address and default route.
		// Frames are switched between veth pairs and the shared ENI.

		// Assign IP address to bridge.
		ipAddress := &ipAddresses[0]
		log.Infof("Assigning IP address %v to bridge link %s.", ipAddress, bridgeName)
		address := &netlink.Addr{IPNet: ipAddress}
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
	} else {
		// In layer3 configuration, the IP address and default route remain on the shared ENI.
		// IP datagrams are routed between the bridge and the shared ENI.

		if vpc.ListContainsIPv4Address(ipAddresses) {
			// Bridge proxies ARP requests originating from veth pairs to the VPC.
			log.Infof("Enabling IPv4 proxy ARP on %s.", bridgeName)
			err = ipcfg.SetIPv4ProxyARP(bridgeName, 1)
			if err != nil {
				log.Errorf("Failed to enable IPv4 proxy ARP on %s: %v.", bridgeName, err)
				return 0, err
			}

			// Enable IPv4 forwarding on the bridge and shared ENI, so that IP datagrams can be
			// routed between them.
			log.Infof("Enabling IPv4 forwarding on %s.", bridgeName)
			err = ipcfg.SetIPv4Forwarding(bridgeName, 1)
			if err != nil {
				log.Errorf("Failed to enable IPv4 forwarding on %s: %v.", bridgeName, err)
				return 0, err
			}

			log.Infof("Enabling IPv4 forwarding on %s.", sharedENI.GetLinkName())
			err = ipcfg.SetIPv4Forwarding(sharedENI.GetLinkName(), 1)
			if err != nil {
				log.Errorf("Failed to enable IPv4 forwarding on %s: %v.", sharedENI.GetLinkName(), err)
				return 0, err
			}

			// Set IPv4 proxy delay to 0 to avoid ARP proxy delays
			log.Infof("Setting IPv4 proxy delay on %s.", sharedENI.GetLinkName())
			err = ipcfg.SetIPv4ProxyDelay(sharedENI.GetLinkName(), 0)
			if err != nil {
				log.Errorf("Failed to set IPv4 proxy delay on %s: %v", sharedENI.GetLinkName(), err)
			}
		}

		if vpc.ListContainsIPv6Address(ipAddresses) {
			// Eanble IPv6 forwarding on all interfaces.
			log.Infof("Enabling IPv6 forwarding on all.")
			err = ipcfg.SetIPv6Forwarding("all", 1)
			if err != nil {
				log.Errorf("Failed to enable IPv6 forwarding on all: %v.", err)
				return 0, err
			}

			log.Infof("Enabling IPv6 accept RA on %s.", bridgeName)
			err = ipcfg.SetIPv6AcceptRA(bridgeName, 2)
			if err != nil {
				log.Errorf("Failed to enable IPv6 accept RA on %s: %v.", bridgeName, err)
				return 0, err
			}

			log.Infof("Enabling IPv6 accept RA on %s.", sharedENI.GetLinkName())
			err = ipcfg.SetIPv6AcceptRA(sharedENI.GetLinkName(), 2)
			if err != nil {
				log.Errorf("Failed to enable IPv6 accept RA on %s: %v.", sharedENI.GetLinkName(), err)
				return 0, err
			}
		}
	}

	return bridgeLink.Attrs().Index, nil
}

// deleteBridge deletes the bridge connected to the shared ENI.
func (nb *BridgeBuilder) deleteBridge(
	bridgeName string,
	bridgeType string,
	sharedENI *eni.ENI) error {

	// Delete bridge layer2 configuration.
	if bridgeType == config.BridgeTypeL2 {
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

		if err != nil && !os.IsNotExist(err) {
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

		if err != nil && !os.IsNotExist(err) {
			log.Errorf("Failed to delete SNAT rule for ENI link %s: %v.", sharedENI, err)
			return err
		}
	}

	// Delete the dummy link for the bridge.
	la := netlink.NewLinkAttrs()
	la.Name = fmt.Sprintf(dummyNameFormat, bridgeName)
	dummyLink := &netlink.Dummy{LinkAttrs: la}
	log.Infof("Deleting dummy link %+v.", dummyLink)
	err := netlink.LinkDel(dummyLink)
	if err != nil && !os.IsNotExist(err) {
		log.Errorf("Failed to delete dummy link: %v.", err)
		return err
	}

	// Delete the bridge.
	la = netlink.NewLinkAttrs()
	la.Name = bridgeName
	bridgeLink := &netlink.Bridge{LinkAttrs: la}
	log.Infof("Deleting bridge link %+v.", bridgeLink)
	err = netlink.LinkDel(bridgeLink)
	if err != nil && !os.IsNotExist(err) {
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
	ipAddresses []net.IPNet,
	gatewayIPAddresses []net.IP,
	gatewayMACAddress net.HardwareAddr) (net.HardwareAddr, error) {

	// Check if the container interface already exists.
	link, err := netlink.LinkByName(ifName)
	if err == nil {
		log.Infof("Found existing container interface  %s.", ifName)
		return link.Attrs().HardwareAddr, nil
	}

	switch ifType {
	case config.IfTypeVETH:
		err = nb.setupVethLink(vethPeerName, ifName, ipAddresses, gatewayIPAddresses, gatewayMACAddress)
	case config.IfTypeTAP:
		err = nb.setupTapLink(vethPeerName, ifName, tapUserID)
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
	ipAddresses []net.IPNet,
	gatewayIPAddresses []net.IP,
	gatewayMACAddress net.HardwareAddr) error {

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

	// Assign IP addresses.
	for _, ipAddress := range ipAddresses {
		if ipAddress.IP.To4() == nil {
			// Disable IPv6 duplicate address detection to speed up address assignment.
			// Linux does not implement DAD for IPv4 addresses.
			log.Infof("Disabling IPv6 accept DAD on %s.", ifName)
			err = ipcfg.SetIPv6AcceptDAD(ifName, 0)
			if err != nil {
				log.Errorf("Failed to disable IPv6 accept DAD on %s: %v.", ifName, err)
				return err
			}
		}

		log.Infof("Assigning IP address %v to link %s.", ipAddress, ifName)
		address := &netlink.Addr{IPNet: &ipAddress}
		err = netlink.AddrAdd(link, address)
		if err != nil {
			log.Errorf("Failed to assign IP address to link %v: %v.", ifName, err)
			return err
		}
	}

	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		log.Errorf("Failed to find link index: %v.", err)
		return err
	}

	// Set default routes.
	for _, gatewayIPAddress := range gatewayIPAddresses {
		// Add default route to the specified gateway on the veth link.
		route := &netlink.Route{
			LinkIndex: iface.Index,
			Gw:        gatewayIPAddress,
			Flags:     int(netlink.FLAG_ONLINK),
		}

		log.Infof("Adding default IP route %+v.", route)
		err = netlink.RouteAdd(route)
		if err != nil {
			log.Errorf("Failed to add IP route %+v: %v.", route, err)
			return err
		}

		// Add a permanent neighbor entry for the IPv4 gateway if a MAC address is specified.
		if gatewayMACAddress != nil && gatewayIPAddress.To4() != nil {
			neigh := &netlink.Neigh{
				LinkIndex:    iface.Index,
				Family:       netlink.FAMILY_V4,
				State:        netlink.NUD_PERMANENT,
				IP:           gatewayIPAddress,
				HardwareAddr: gatewayMACAddress,
			}

			log.Infof("Adding neighbor entry for gateway %+v.", neigh)
			err = netlink.NeighAdd(neigh)
			if err != nil {
				log.Errorf("Failed to add neighbor %+v: %v.", neigh, err)
				return err
			}
		}
	}

	return nil
}

// setupTapLink sets up a TAP link in the target network namespace.
func (nb *BridgeBuilder) setupTapLink(linkName string, tapLinkName string, uid int) error {
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
