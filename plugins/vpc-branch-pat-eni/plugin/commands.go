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
	"fmt"
	"net"
	"syscall"

	"github.com/aws/amazon-vpc-cni-plugins/network/eni"
	"github.com/aws/amazon-vpc-cni-plugins/network/iptables"
	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-branch-pat-eni/config"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesCurrent "github.com/containernetworking/cni/pkg/types/current"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// Name templates used for objects created by this plugin.
	patNetNSNameFormat   = "vpc-pat-%d"
	branchLinkNameFormat = "%s.%d"
	bridgeName           = "virbr0"
	tapBridgeNameFormat  = "tapbr%d"

	// Static IP address assigned to the PAT bridge.
	bridgeIPAddressString = "192.168.122.1/24"

	// maxRetriesVethPairNameCollision specifies the maximum number of times
	// veth pair creation will be retried if there's a name collision.
	maxRetriesVethPairNameCollision = 3

	// linkDeviceTypeVethPair specifies the link device type string for a
	// veth pair device. The names for different device types can be found
	// by running the "ip link help" command.
	linkDeviceTypeVethPair = "veth"
)

// Add is the internal implementation of CNI ADD command.
func (plugin *Plugin) Add(args *cniSkel.CmdArgs) error {
	// Parse network configuration.
	netConfig, err := config.New(args, true)
	if err != nil {
		log.Errorf("Failed to parse netconfig from args: %v.", err)
		return err
	}

	log.Infof("Executing ADD with netconfig: %+v.", netConfig)

	// Derive names from CNI network config.
	patNetNSName := fmt.Sprintf(patNetNSNameFormat, netConfig.BranchVlanID)
	tapBridgeName := fmt.Sprintf(tapBridgeNameFormat, netConfig.BranchVlanID)
	tapLinkName := args.IfName
	targetNetNSName := args.Netns

	// Search for the target network namespace.
	log.Infof("Searching for target netns %s.", targetNetNSName)
	targetNetNS, err := netns.GetNetNSByName(targetNetNSName)
	if err != nil {
		log.Errorf("Failed to find target netns %s.", targetNetNSName)
		return err
	}

	// Create the trunk ENI.
	trunk, err := eni.NewTrunk(netConfig.TrunkName, netConfig.TrunkMACAddress, eni.TrunkIsolationModeVLAN)
	if err != nil {
		log.Errorf("Failed to find trunk interface %s: %v.", netConfig.TrunkName, err)
		return err
	}

	// Search for the PAT network namespace.
	log.Infof("Searching for PAT netns %s.", patNetNSName)
	patNetNS, err := netns.GetNetNSByName(patNetNSName)
	if err != nil {
		// This is the first PAT interface request on this VLAN ID.
		// Create the PAT network namespace.
		branchName := fmt.Sprintf(branchLinkNameFormat, trunk.GetLinkName(), netConfig.BranchVlanID)

		// Compute the branch ENI's VPC subnet.
		branchSubnetPrefix := vpc.GetSubnetPrefix(&netConfig.BranchIPAddress)
		branchSubnet, _ := vpc.NewSubnet(branchSubnetPrefix)
		bridgeIPAddress, _ := vpc.GetIPAddressFromString(bridgeIPAddressString)

		patNetNS, err = plugin.createPATNetworkNamespace(
			patNetNSName, trunk,
			branchName, netConfig.BranchMACAddress, netConfig.BranchVlanID,
			&netConfig.BranchIPAddress, branchSubnet, bridgeIPAddress)

		if err != nil {
			log.Errorf("Failed to setup PAT netns %s: %v.", patNetNSName, err)
			return err
		}
	} else {
		// Reuse the PAT network namespace that was setup on this VLAN ID during a previous request.
		log.Infof("Found PAT netns %s.", patNetNSName)
	}

	// Create the veth pair in PAT network namespace.
	var vethPeerName string
	err = patNetNS.Run(func() error {
		var verr error
		vethPeerName, verr = plugin.createVethPair(
			netConfig.BranchVlanID, args.ContainerID, bridgeName, targetNetNS)
		return verr
	})
	if err != nil {
		log.Errorf("Failed to create veth pair: %v.", err)
		return err
	}

	// Create the tap link in target network namespace.
	log.Infof("Creating tap link %s.", tapLinkName)
	err = targetNetNS.Run(func() error {
		return plugin.createTapLink(tapBridgeName, vethPeerName, tapLinkName, netConfig.Uid, netConfig.Gid)
	})
	if err != nil {
		log.Errorf("Failed to create tap link: %v.", err)
		return err
	}

	// Generate CNI result.
	// IP addresses, routes and DNS are configured by VPC DHCP servers.
	result := &cniTypesCurrent.Result{
		Interfaces: []*cniTypesCurrent.Interface{
			{
				Name:    tapLinkName,
				Mac:     netConfig.BranchMACAddress.String(),
				Sandbox: targetNetNSName,
			},
		},
	}

	log.Infof("Writing CNI result to stdout: %+v.", result)

	return cniTypes.PrintResult(result, netConfig.CNIVersion)
}

// Del is the internal implementation of CNI DEL command.
// CNI DEL command can be called by the orchestrator agent multiple times for the same interface,
// and thus must be best-effort and idempotent.
func (plugin *Plugin) Del(args *cniSkel.CmdArgs) error {
	// Parse network configuration.
	netConfig, err := config.New(args, false)
	if err != nil {
		log.Errorf("Failed to parse netconfig from args: %v.", err)
		return err
	}

	log.Infof("Executing DEL with netconfig: %+v.", netConfig)

	// Derive names from CNI network config.
	patNetNSName := fmt.Sprintf(patNetNSNameFormat, netConfig.BranchVlanID)
	tapBridgeName := fmt.Sprintf(tapBridgeNameFormat, netConfig.BranchVlanID)
	tapLinkName := args.IfName
	targetNetNSName := args.Netns

	// Delete the tap link and veth pair from the target netns.
	plugin.deleteTapVethLinks(targetNetNSName, tapLinkName, tapBridgeName)

	// Search for the PAT network namespace.
	patNetNS, err := netns.GetNetNSByName(patNetNSName)
	if err != nil {
		// Log and ignore the failure. DEL can be called multiple times and thus must be idempotent.
		log.Errorf("Failed to find netns %s, ignoring: %v.", patNetNSName, err)
		return nil
	}
	lastVethLinkDeleted := false

	// In PAT network namespace...
	err = patNetNS.Run(func() error {
		// Check whether there are any remaining veth links connected to this bridge.
		ifaces, _ := net.Interfaces()
		log.Infof("Number of remaining links: %v.", len(ifaces))
		if len(ifaces) == 4 {
			// Only VLAN link, bridge, dummy and loopback remain.
			lastVethLinkDeleted = true
		}

		return nil
	})

	// If all veth links connected to this PAT bridge are deleted, clean up the PAT network
	// namespace and all virtual interfaces in it. Otherwise, leave it running.
	if lastVethLinkDeleted && netConfig.CleanupPATNetNS {
		log.Infof("Deleting PAT network namespace: %v.", patNetNSName)
		err = patNetNS.Close()
		if err != nil {
			log.Errorf("Failed to delete netns: %v.", err)
		}
	} else {
		log.Infof("Skipping PAT netns deletion. Last veth link deleted: %t, cleanup PAT netns: %t.",
			lastVethLinkDeleted, netConfig.CleanupPATNetNS)
	}

	return nil
}

// createPATNetworkNamespace creates the PAT network namespace for the specified branch interface.
func (plugin *Plugin) createPATNetworkNamespace(
	patNetNSName string,
	trunk *eni.Trunk,
	branchName string,
	branchMACAddress net.HardwareAddr,
	branchVlanID int,
	branchIPAddress *net.IPNet,
	branchSubnet *vpc.Subnet,
	bridgeIPAddress *net.IPNet) (netns.NetNS, error) {
	// Create the PAT network namespace.
	log.Infof("Creating PAT netns %s.", patNetNSName)
	patNetNS, err := netns.NewNetNS(patNetNSName)
	if err != nil {
		log.Errorf("Failed to create PAT netns %s: %v.", patNetNSName, err)
		return nil, err
	}

	// Create the branch ENI.
	branch, err := eni.NewBranch(trunk, branchName, branchMACAddress, branchVlanID)
	if err != nil {
		log.Errorf("Failed to create branch interface %s in PAT netns %s: %v.",
			branchName, patNetNSName, err)
		return nil, err
	}

	// Create a link for the branch ENI.
	log.Infof("Creating branch link %s in PAT netns %s.", branchName, patNetNSName)
	if err = branch.AttachToLink(true); err != nil {
		log.Errorf("Failed to attach branch interface %s in %s: %v.",
			branchName, patNetNSName, err)
		return nil, err
	}

	// Move branch ENI to the PAT network namespace.
	log.Infof("Moving branch link %s to PAT netns %s.", branchName, patNetNSName)
	if err = branch.SetNetNS(patNetNS); err != nil {
		log.Errorf("Failed to move branch link %s to PAT netns %s: %v.",
			branchName, patNetNSName, err)
		return nil, err
	}

	// Configure the PAT network namespace.
	log.Infof("Setting up PAT netns %s.", patNetNSName)
	err = patNetNS.Run(func() error {
		return plugin.setupPATNetworkNamespace(patNetNSName,
			bridgeName, bridgeIPAddress, branch, branchIPAddress, branchSubnet)
	})
	if err != nil {
		log.Errorf("Failed to setup PAT netns %s: %v.", patNetNSName, err)
		return nil, err
	}
	return patNetNS, nil
}

// setupPATNetworkNamespace configures all networking inside the PAT network namespace.
func (plugin *Plugin) setupPATNetworkNamespace(
	patNetNSName string,
	bridgeName string, bridgeIPAddress *net.IPNet,
	branch *eni.Branch, branchIPAddress *net.IPNet, branchSubnet *vpc.Subnet) error {

	// Create the bridge link.
	la := netlink.NewLinkAttrs()
	la.Name = bridgeName
	la.MTU = vpc.JumboFrameMTU
	bridgeLink := &netlink.Bridge{LinkAttrs: la}
	log.Infof("Creating bridge link %+v in PAT netns %s.", bridgeLink, patNetNSName)
	err := netlink.LinkAdd(bridgeLink)
	if err != nil {
		log.Errorf("Failed to create bridge link in PAT netns %s: %v.", patNetNSName, err)
		return err
	}

	// Set bridge link MTU.
	err = netlink.LinkSetMTU(bridgeLink, vpc.JumboFrameMTU)
	if err != nil {
		log.Errorf("Failed to set bridge link MTU in PAT netns %s: %v.", patNetNSName, err)
		return err
	}

	// Create the dummy link.
	la = netlink.NewLinkAttrs()
	la.Name = fmt.Sprintf("%s-dummy", bridgeName)
	la.MTU = vpc.JumboFrameMTU
	la.MasterIndex = bridgeLink.Index
	dummyLink := &netlink.Dummy{LinkAttrs: la}
	log.Infof("Creating dummy link %+v in PAT netns %s.", dummyLink, patNetNSName)
	err = netlink.LinkAdd(dummyLink)
	if err != nil {
		log.Errorf("Failed to create dummy link in PAT netns %s: %v.", patNetNSName, err)
		return err
	}

	// Set dummy link MTU.
	err = netlink.LinkSetMTU(dummyLink, vpc.JumboFrameMTU)
	if err != nil {
		log.Errorf("Failed to set dummy link MTU in PAT netns %s: %v.", patNetNSName, err)
		return err
	}

	// Assign IP address to PAT bridge.
	log.Infof("Assigning IP address %v to bridge link %s in PAT netns %s.",
		bridgeIPAddress, bridgeName, patNetNSName)
	address := &netlink.Addr{IPNet: bridgeIPAddress}
	err = netlink.AddrAdd(bridgeLink, address)
	if err != nil {
		log.Errorf("Failed to assign IP address to bridge link in PAT netns %s: %v.",
			patNetNSName, err)
		return err
	}

	// Set bridge link operational state up.
	log.Infof("Setting bridge link state up in PAT netns %s.", patNetNSName)
	err = netlink.LinkSetUp(bridgeLink)
	if err != nil {
		log.Errorf("Failed to set bridge link state in PAT netns %s: %v.", patNetNSName, err)
		return err
	}

	// TODO: brctl stp #{pat_bridge_interface_name} off

	// Assign IP address to branch interface.
	log.Infof("Assigning IP address %v to branch link in PAT netns %s.",
		branchIPAddress, patNetNSName)
	address = &netlink.Addr{IPNet: branchIPAddress}
	la = netlink.NewLinkAttrs()
	la.Index = branch.GetLinkIndex()
	link := &netlink.Dummy{LinkAttrs: la}
	err = netlink.AddrAdd(link, address)
	if err != nil {
		log.Errorf("Failed to assign IP address to branch link in PAT netns %s: %v.",
			patNetNSName, err)
		return err
	}

	// Set branch link operational state up.
	log.Infof("Setting branch link state up in PAT netns %s.", patNetNSName)
	err = branch.SetOpState(true)
	if err != nil {
		log.Errorf("Failed to set branch link state in PAT netns %s: %v.", patNetNSName, err)
		return err
	}

	// Add default route to PAT branch gateway.
	route := &netlink.Route{
		Gw:        branchSubnet.Gateways[0],
		LinkIndex: branch.GetLinkIndex(),
	}
	log.Infof("Adding default route to %+v in PAT netns %s.", route, patNetNSName)
	err = netlink.RouteAdd(route)
	if err != nil {
		log.Errorf("Failed to add IP route in PAT netns %s: %v.", patNetNSName, err)
		return err
	}

	// Configure iptables rules.
	log.Infof("Configuring iptables rules in PAT netns %s.", patNetNSName)
	_, bridgeSubnet, _ := net.ParseCIDR(bridgeIPAddress.String())
	err = plugin.setupIptablesRules(bridgeName, bridgeSubnet.String(), branch.GetLinkName())
	if err != nil {
		log.Errorf("Unable to setup iptables rules in PAT netns %s: %v.", patNetNSName, err)
		return err
	}

	return nil
}

// setupIptablesRules sets iptables rules in PAT network namespace.
func (plugin *Plugin) setupIptablesRules(bridgeName, bridgeSubnet, branchLinkName string) error {
	// Create a new iptables session.
	s, err := iptables.NewSession()
	if err != nil {
		return err
	}

	// Allow DNS.
	s.Filter.Input.Appendf("-i %s -p udp -m udp --dport 53 -j ACCEPT", bridgeName)
	s.Filter.Input.Appendf("-i %s -p tcp -m tcp --dport 53 -j ACCEPT", bridgeName)
	// Allow BOOTP/DHCP server.
	s.Filter.Input.Appendf("-i %s -p udp -m udp --dport 67 -j ACCEPT", bridgeName)
	s.Filter.Input.Appendf("-i %s -p tcp -m tcp --dport 67 -j ACCEPT", bridgeName)

	//
	s.Filter.Forward.Appendf("-d %s -i %s -o %s -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
		bridgeSubnet, branchLinkName, bridgeName)
	s.Filter.Forward.Appendf("-s %s -i %s -o %s -j ACCEPT",
		bridgeSubnet, bridgeName, branchLinkName)
	s.Filter.Forward.Appendf("-i %s -o %s -j ACCEPT", bridgeName, bridgeName)

	// Reject all traffic originating from or delivered to the bridge itself.
	s.Filter.Forward.Appendf("-o %s -j REJECT --reject-with icmp-port-unreachable", bridgeName)
	s.Filter.Forward.Appendf("-i %s -j REJECT --reject-with icmp-port-unreachable", bridgeName)

	// Allow BOOTP/DHCP client.
	s.Filter.Output.Appendf("-o %s -p udp -m udp --dport 68 -j ACCEPT", bridgeName)

	// Allow IPv4 multicast.
	// TODO: Replace these two with a -unicast switch in MASQ rule.
	s.Nat.Postrouting.Appendf("-s %s -d 224.0.0.0/24 -o %s -j RETURN", bridgeSubnet, branchLinkName)
	// Allow IPv4 broadcast.
	s.Nat.Postrouting.Appendf("-s %s -d 255.255.255.255/32 -o %s -j RETURN", bridgeSubnet, branchLinkName)

	// Masquerade all unicast IP datagrams leaving the PAT bridge.
	s.Nat.Postrouting.Appendf("-s %s ! -d %s -o %s -p tcp -j MASQUERADE --to-ports 1024-65535",
		bridgeSubnet, bridgeSubnet, branchLinkName)
	s.Nat.Postrouting.Appendf("-s %s ! -d %s -o %s -p udp -j MASQUERADE --to-ports 1024-65535",
		bridgeSubnet, bridgeSubnet, branchLinkName)
	s.Nat.Postrouting.Appendf("-s %s ! -d %s -o %s -j MASQUERADE",
		bridgeSubnet, bridgeSubnet, branchLinkName)

	// Compute UDP checksum for DHCP client traffic from bridge.
	s.Mangle.Postrouting.Appendf("-o %s -p udp -m udp --dport 68 -j CHECKSUM --checksum-fill", bridgeName)

	// Commit all rules in this session atomically.
	err = s.Commit(nil)
	if err != nil {
		log.Errorf("Failed to commit iptables rules: %v.", err)
	}

	return err
}

// createVethPair creates a veth pair to connect a PAT network namespace to a target network namespace.
func (plugin *Plugin) createVethPair(
	branchVlanID int,
	containerID string,
	bridgeName string,
	targetNetNS netns.NetNS) (string, error) {
	var vethLinkName, vethPeerName string
	var err error
	// Attempt to create the veth pair. The create attempt will be retried if a device
	// with the name already exists, up to 3 times.
	generateRandomName := false
	for i := 0; i < maxRetriesVethPairNameCollision; i++ {
		vethLinkName, vethPeerName = generateVethPairNames(branchVlanID, containerID, generateRandomName)
		err = plugin.createVethPairOnce(bridgeName, targetNetNS, vethLinkName, vethPeerName)
		if err == nil {
			// Successfully created veth pair, return.
			return vethPeerName, nil
		}
		if err != syscall.EEXIST {
			// Return from the method for any error other than 'device exists'.
			return "", err
		}
		// Possible veth pair name collision. Regenerate veth link and its peer's name.
		generateRandomName = true
		log.Warnf("Veth pair %s exists [%v].", vethLinkName, err)
	}

	return vethPeerName, err
}

// createVethPairOnce creates a veth pair to connect a PAT network namespace to a target network namespace.
func (plugin *Plugin) createVethPairOnce(
	bridgeName string,
	targetNetNS netns.NetNS,
	vethLinkName string,
	vethPeerName string) error {
	// Find the PAT bridge.
	bridge, err := net.InterfaceByName(bridgeName)
	if err != nil {
		log.Errorf("Failed to find bridge %s: %v.", bridgeName, err)
		return err
	}

	// Create the veth link and connect it to the bridge.
	la := netlink.NewLinkAttrs()
	la.Name = vethLinkName
	la.MasterIndex = bridge.Index
	la.MTU = vpc.JumboFrameMTU
	vethLink := &netlink.Veth{
		LinkAttrs: la,
		PeerName:  vethPeerName,
	}

	log.Infof("Creating veth pair %+v.", vethLink)
	err = netlink.LinkAdd(vethLink)
	if err != nil {
		log.Errorf("Failed to add veth pair (%s, %s): %v.",
			vethLinkName, vethPeerName, err)
		return err
	}

	// Move the veth link's peer to target network namespace.
	log.Infof("Moving veth link peer %s to target netns.", vethPeerName)
	la = netlink.NewLinkAttrs()
	la.Name = vethPeerName
	vethPeer := &netlink.Dummy{LinkAttrs: la}
	err = netlink.LinkSetNsFd(vethPeer, int(targetNetNS.GetFd()))
	if err != nil {
		log.Errorf("Failed to move veth link peer %s to target netns: %v.",
			vethPeerName, err)
		return err
	}

	// Set the veth link operational state up
	log.Infof("Setting the veth link %s state up.", vethLinkName)
	err = netlink.LinkSetUp(vethLink)
	if err != nil {
		log.Errorf("Failed to bring up veth link %s: %v.",
			vethLinkName, err)
		return err
	}
	return nil
}

// createTapLink creates a tap link and attaches it to the bridge.
func (plugin *Plugin) createTapLink(
	bridgeName string,
	vethLinkName string,
	tapLinkName string,
	uid int,
	gid int) error {

	// Create the bridge link.
	la := netlink.NewLinkAttrs()
	la.Name = bridgeName
	la.MTU = vpc.JumboFrameMTU
	bridge := &netlink.Bridge{LinkAttrs: la}
	log.Infof("Creating tap bridge %+v.", bridge)
	err := netlink.LinkAdd(bridge)
	if err != nil {
		log.Errorf("Failed to create tap bridge %s: %v.", bridgeName, err)
		return err
	}

	// Set bridge link MTU.
	err = netlink.LinkSetMTU(bridge, vpc.JumboFrameMTU)
	if err != nil {
		log.Errorf("Failed to set tap bridge %s link MTU: %v.",
			bridgeName, err)
		return err
	}

	// Connect veth link to the bridge.
	la = netlink.NewLinkAttrs()
	la.Name = vethLinkName
	vethLink := &netlink.Dummy{LinkAttrs: la}
	err = netlink.LinkSetMaster(vethLink, bridge)
	if err != nil {
		log.Errorf("Failed to set veth link %s master to %s: %v.",
			vethLinkName, bridgeName, err)
		return err
	}

	// Create the tap link.
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

	log.Infof("Creating tap link %+v.", tapLink)
	err = netlink.LinkAdd(tapLink)
	if err != nil {
		log.Errorf("Failed to add tap link %s: %v.", tapLinkName, err)
		return err
	}

	// Set tap link MTU.
	err = netlink.LinkSetMTU(tapLink, vpc.JumboFrameMTU)
	if err != nil {
		log.Errorf("Failed to set tap link %s MTU: %v.", tapLinkName, err)
		return err
	}

	// Set tap link ownership.
	log.Infof("Setting tap link %s owner to uid %d and gid %d.", tapLinkName, uid, gid)
	fd := int(tapLink.Fds[0].Fd())
	err = unix.IoctlSetInt(fd, unix.TUNSETOWNER, uid)
	if err != nil {
		log.Errorf("Failed to set tap link %s uid: %v.", tapLinkName, err)
		return err
	}
	err = unix.IoctlSetInt(fd, unix.TUNSETGROUP, gid)
	if err != nil {
		log.Errorf("Failed to set tap link %s gid: %v.", tapLinkName, err)
		return err
	}

	// Set the bridge link operational state up
	log.Infof("Setting bridge link %s state up.", bridgeName)
	err = netlink.LinkSetUp(bridge)
	if err != nil {
		log.Errorf("Failed to set bridge link %s state: %v.", bridgeName, err)
		return err
	}

	// Set tap link operational state up.
	log.Infof("Setting tap link %s state up.", tapLinkName)
	err = netlink.LinkSetUp(tapLink)
	if err != nil {
		log.Errorf("Failed to set tap link %s state: %v.", tapLinkName, err)
		return err
	}

	// Set the veth peer link operational state up.
	log.Infof("Setting veth peer link %s state up.", vethLinkName)
	err = netlink.LinkSetUp(vethLink)
	if err != nil {
		log.Errorf("Failed to set veth peer %s link state: %v.", vethLinkName, err)
		return err
	}

	return nil
}

// deleteTapVethLinks deletes tap link and veth peer link from the target netns.
func (plugin *Plugin) deleteTapVethLinks(
	targetNetNSName string,
	tapLinkName string,
	tapBridgeName string) {
	// Search for the target network namespace.
	targetNetNS, err := netns.GetNetNSByName(targetNetNSName)
	if err != nil {
		// Log and ignore the failure. DEL can be called multiple times and thus must be idempotent.
		log.Errorf("Failed to find netns %s, ignoring: %v.", targetNetNSName, err)
		return
	}

	// In target network namespace...
	err = targetNetNS.Run(func() error {
		// Delete the tap link.
		la := netlink.NewLinkAttrs()
		la.Name = tapLinkName
		tapLink := &netlink.Tuntap{LinkAttrs: la}
		log.Infof("Deleting tap link: %v.", tapLinkName)
		err = netlink.LinkDel(tapLink)
		if err != nil {
			log.Errorf("Failed to delete tap link %s: %v.", tapLinkName, err)
		}

		// Delete the veth peer.
		deleteVethPeerByNameRegex(targetNetNSName)

		// Delete the tap bridge.
		la = netlink.NewLinkAttrs()
		la.Name = tapBridgeName
		tapBridge := &netlink.Bridge{LinkAttrs: la}
		log.Infof("Deleting tap bridge: %v.", tapBridgeName)
		err = netlink.LinkDel(tapBridge)
		if err != nil {
			log.Errorf("Failed to delete tap bridge %s: %v.", tapBridgeName, err)
		}

		return nil
	})
}

// deleteVethPeerByNameRegex deletes a veth peer device in the target namespace
// if the name matches the regex used to create the veth pair link device.
func deleteVethPeerByNameRegex(targetNetNSName string) {
	// Veth pair cannot be deleted by name as a random name could
	// have been generated for it in Add(). Find it by type instead.
	linkDevs, err := netlink.LinkList()
	if err != nil {
		log.Errorf("Failed to list links in %s: %v.", targetNetNSName, err)
		return
	}
	for _, link := range linkDevs {
		linkName := link.Attrs().Name
		if link.Type() == linkDeviceTypeVethPair && vethPeerNameRecognizable(linkName) {
			log.Infof("Deleting veth link: %v.", linkName)
			err = netlink.LinkDel(link)
			if err != nil {
				log.Errorf("Failed to delete veth pair%s: %v.", linkName, err)
			}
			// The veth pair device was found and an attempt was made to delete
			// the same. Nothing left to do.
			return
		}
	}

}
