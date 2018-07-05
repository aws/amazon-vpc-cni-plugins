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
	"strconv"

	"github.com/aws/amazon-vpc-cni-plugins/network/eni"
	"github.com/aws/amazon-vpc-cni-plugins/network/iptables"
	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-branch-pat-eni/config"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniCurrent "github.com/containernetworking/cni/pkg/types/current"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// Name templates used for objects created by this plugin.
	patNetNSNameFormat   = "vpc-pat-%s"
	branchLinkNameFormat = "%s.%s"
	vethLinkNameFormat   = "veth%s-%s"
	bridgeName           = "virbr0"
	tapBridgeNameFormat  = "tapbr%s"

	// Static IP address assigned to the PAT bridge.
	bridgeIPAddressString = "192.168.122.1/24"
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
	// All fields have already been validated during parsing.
	patNetNSName := fmt.Sprintf(patNetNSNameFormat, netConfig.BranchVlanID)
	bridgeIPAddress, _ := vpc.GetIPAddressFromString(bridgeIPAddressString)
	branchName := fmt.Sprintf(branchLinkNameFormat, netConfig.TrunkName, netConfig.BranchVlanID)
	branchMACAddress, _ := net.ParseMAC(netConfig.BranchMACAddress)
	branchVlanID, _ := strconv.Atoi(netConfig.BranchVlanID)

	// Compute the branch ENI's VPC subnet.
	branchSubnet, err := vpc.NewSubnet(netConfig.BranchIPAddress)
	branchIPAddress, _ := vpc.GetIPAddressFromString(netConfig.BranchIPAddress)

	vethLinkName := fmt.Sprintf(vethLinkNameFormat, netConfig.BranchVlanID, args.ContainerID)
	vethPeerName := vethLinkName + "-2"
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

	// Lookup the user ID for TAP link.
	uid, err := plugin.CNIPlugin.LookupUser(netConfig.UserName)
	if err != nil {
		log.Errorf("Failed to lookup user %s: %v.", netConfig.UserName, err)
		return err
	}
	log.Infof("Lookup for username %s returned uid %d.", netConfig.UserName, uid)

	// Create the trunk ENI.
	trunk, err := eni.NewTrunk(netConfig.TrunkName, eni.TrunkIsolationModeVLAN)
	if err != nil {
		log.Errorf("Failed to find trunk interface %s: %v.", netConfig.TrunkName, err)
		return err
	}

	// Search for the PAT network namespace.
	log.Infof("Searching for PAT netns %s.", patNetNSName)
	patNetNS, err := netns.GetNetNSByName(patNetNSName)
	if err != nil {
		log.Infof("PAT netns %s does not exist.", patNetNSName)

		// Create the PAT network namespace.
		log.Infof("Creating PAT netns %s.", patNetNSName)
		patNetNS, err = netns.NewNetNS(patNetNSName)
		if err != nil {
			log.Errorf("Failed to create PAT netns: %v.", err)
			return err
		}

		// Create the branch ENI.
		branch, err := eni.NewBranch(trunk, branchName, branchMACAddress, branchVlanID)
		if err != nil {
			log.Errorf("Failed to create branch interface %s: %v.", branchName, err)
			return err
		}

		// Create a link for the branch ENI.
		log.Infof("Creating branch link %s.", branchName)
		err = branch.AttachToLink(false)
		if err != nil {
			log.Errorf("Failed to attach branch interface %s: %v.", branchName, err)
			return err
		}

		// Move branch ENI to the PAT network namespace.
		log.Infof("Moving branch link to PAT netns.")
		err = branch.SetNetNS(patNetNS)
		if err != nil {
			log.Errorf("Failed to move branch link: %v.", err)
			return err
		}

		// Configure the PAT network namespace.
		log.Infof("Setting up PAT netns %s.", patNetNSName)
		err = patNetNS.Run(func() error {
			return plugin.setupPATNetworkNamespace(
				bridgeName, bridgeIPAddress, branch, branchIPAddress, branchSubnet)
		})
		if err != nil {
			log.Errorf("Failed to setup PAT netns: %v.", err)
			return err
		}
	} else {
		log.Infof("Found PAT netns %s.", patNetNSName)
	}

	// Create the veth pair in PAT network namespace.
	log.Infof("Creating veth pair %s.", vethLinkName)
	err = patNetNS.Run(func() error {
		return plugin.createVethPair(bridgeName, targetNetNS, vethLinkName, vethPeerName)
	})
	if err != nil {
		log.Errorf("Failed to create veth pair: %v.", err)
		return err
	}

	// Create the tap link in target network namespace.
	log.Infof("Creating tap link %s.", tapLinkName)
	err = targetNetNS.Run(func() error {
		return plugin.createTapLink(tapBridgeName, vethPeerName, tapLinkName, uid)
	})
	if err != nil {
		log.Errorf("Failed to create tap link: %v.", err)
		return err
	}

	// Generate CNI result.
	// IP addresses, routes and DNS are configured by VPC DHCP servers.
	result := &cniCurrent.Result{
		Interfaces: []*cniCurrent.Interface{
			{
				Name:    tapLinkName,
				Mac:     branchMACAddress.String(),
				Sandbox: targetNetNSName,
			},
		},
	}

	log.Infof("Writing CNI result to stdout: %+v", result)

	return cniTypes.PrintResult(result, netConfig.CNIVersion)
}

// Del is the internal implementation of CNI DEL command.
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
	vethLinkName := fmt.Sprintf(vethLinkNameFormat, netConfig.BranchVlanID, args.ContainerID)
	vethPeerName := vethLinkName + "-2"
	tapBridgeName := fmt.Sprintf(tapBridgeNameFormat, netConfig.BranchVlanID)
	tapLinkName := args.IfName
	targetNetNSName := args.Netns

	// Search for the target network namespace.
	targetNetNS, err := netns.GetNetNSByName(targetNetNSName)
	if err == nil {
		// In target network namespace...
		err = targetNetNS.Run(func() error {
			// Delete the tap link.
			la := netlink.NewLinkAttrs()
			la.Name = tapLinkName
			tapLink := &netlink.Tuntap{LinkAttrs: la}
			log.Infof("Deleting tap link: %v.", tapLinkName)
			err = netlink.LinkDel(tapLink)
			if err != nil {
				log.Errorf("Failed to delete tap link: %v.", err)
			}

			// Delete the veth pair.
			la = netlink.NewLinkAttrs()
			la.Name = vethPeerName
			vethLink := &netlink.Veth{LinkAttrs: la}
			log.Infof("Deleting veth pair: %v.", vethPeerName)
			err = netlink.LinkDel(vethLink)
			if err != nil {
				log.Errorf("Failed to delete veth pair: %v.", err)
			}

			// Delete the tap bridge.
			la = netlink.NewLinkAttrs()
			la.Name = tapBridgeName
			tapBridge := &netlink.Bridge{LinkAttrs: la}
			log.Infof("Deleting tap bridge: %v.", tapBridgeName)
			err = netlink.LinkDel(tapBridge)
			if err != nil {
				log.Errorf("Failed to delete tap bridge: %v.", err)
			}

			return nil
		})
	} else {
		// Log and ignore the failure. DEL can be called multiple times and thus must be idempotent.
		log.Errorf("Failed to find netns %s, ignoring: %v.", targetNetNSName, err)
	}

	// Search for the PAT network namespace.
	patNetNS, err := netns.GetNetNSByName(patNetNSName)
	if err == nil {
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
		if lastVethLinkDeleted {
			log.Infof("Deleting PAT network namespace: %v.", patNetNSName)
			err = patNetNS.Close()
			if err != nil {
				log.Errorf("Failed to delete netns: %v.", err)
			}
		}
	} else {
		// Log and ignore the failure. DEL can be called multiple times and thus must be idempotent.
		log.Errorf("Failed to find netns %s, ignoring: %v.", patNetNSName, err)
	}

	return nil
}

// setupPATNetworkNamespace configures all networking inside the PAT network namespace.
func (plugin *Plugin) setupPATNetworkNamespace(
	bridgeName string, bridgeIPAddress *net.IPNet,
	branch *eni.Branch, branchIPAddress *net.IPNet, branchSubnet *vpc.Subnet) error {

	// Create the bridge link.
	la := netlink.NewLinkAttrs()
	la.Name = bridgeName
	la.MTU = vpc.JumboFrameMTU
	bridgeLink := &netlink.Bridge{LinkAttrs: la}
	log.Infof("Creating bridge link %+v.", bridgeLink)
	err := netlink.LinkAdd(bridgeLink)
	if err != nil {
		log.Errorf("Failed to create bridge link: %v", err)
		return err
	}

	// Set bridge link MTU.
	err = netlink.LinkSetMTU(bridgeLink, vpc.JumboFrameMTU)
	if err != nil {
		log.Errorf("Failed to set bridge link MTU: %v", err)
		return err
	}

	// Create the dummy link.
	la = netlink.NewLinkAttrs()
	la.Name = fmt.Sprintf("%s-dummy", bridgeName)
	la.MTU = vpc.JumboFrameMTU
	la.MasterIndex = bridgeLink.Index
	dummyLink := &netlink.Dummy{LinkAttrs: la}
	log.Infof("Creating dummy link %+v.", dummyLink)
	err = netlink.LinkAdd(dummyLink)
	if err != nil {
		log.Errorf("Failed to create dummy link: %v", err)
		return err
	}

	// Set dummy link MTU.
	err = netlink.LinkSetMTU(dummyLink, vpc.JumboFrameMTU)
	if err != nil {
		log.Errorf("Failed to set dummy link MTU: %v", err)
		return err
	}

	// Assign IP address to PAT bridge.
	log.Infof("Assigning IP address %v to bridge link %s.", bridgeIPAddress, bridgeName)
	address := &netlink.Addr{IPNet: bridgeIPAddress}
	err = netlink.AddrAdd(bridgeLink, address)
	if err != nil {
		log.Errorf("Failed to assign IP address to bridge link: %v", err)
		return err
	}

	// Set bridge link operational state up.
	log.Info("Setting bridge link state up.")
	err = netlink.LinkSetUp(bridgeLink)
	if err != nil {
		log.Errorf("Failed to set bridge link state: %v", err)
		return err
	}

	// TODO: brctl stp #{pat_bridge_interface_name} off

	// Assign IP address to branch interface.
	log.Infof("Assigning IP address %v to branch link.", branchIPAddress)
	address = &netlink.Addr{IPNet: branchIPAddress}
	la = netlink.NewLinkAttrs()
	la.Index = branch.GetLinkIndex()
	link := &netlink.Dummy{LinkAttrs: la}
	err = netlink.AddrAdd(link, address)
	if err != nil {
		log.Errorf("Failed to assign IP address to branch link: %v", err)
		return err
	}

	// Set branch link operational state up.
	log.Info("Setting branch link state up.")
	err = branch.SetOpState(true)
	if err != nil {
		log.Errorf("Failed to set branch link state: %v", err)
		return err
	}

	// Add default route to PAT branch gateway.
	route := &netlink.Route{
		Gw:        branchSubnet.Gateways[0],
		LinkIndex: branch.GetLinkIndex(),
	}
	log.Infof("Adding default route to %+v.", route)
	err = netlink.RouteAdd(route)
	if err != nil {
		log.Errorf("Failed to add IP route: %v", err)
		return err
	}

	// Configure iptables rules.
	log.Info("Configuring iptables rules.")
	_, bridgeSubnet, _ := net.ParseCIDR(bridgeIPAddress.String())
	plugin.setupIptablesRules(bridgeName, bridgeSubnet.String(), branch.GetLinkName())

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
		log.Errorf("Failed to commit iptables rules: %v", err)
	}

	return err
}

// createVethPair creates a veth pair to connect a PAT network namespace to a target network namespace.
func (plugin *Plugin) createVethPair(
	bridgeName string, targetNetNS netns.NetNS,
	vethLinkName string, vethPeerName string) error {
	// Find the PAT bridge.
	bridge, err := net.InterfaceByName(bridgeName)
	if err != nil {
		log.Errorf("Failed to find bridge %s: %v", bridgeName, err)
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
		log.Errorf("Failed to add veth pair: %v", err)
		return err
	}

	// Move the veth link's peer to target network namespace.
	log.Infof("Moving veth link peer to target netns.")
	la = netlink.NewLinkAttrs()
	la.Name = vethPeerName
	vethPeer := &netlink.Dummy{LinkAttrs: la}
	err = netlink.LinkSetNsFd(vethPeer, int(targetNetNS.GetFd()))
	if err != nil {
		log.Errorf("Failed to move veth link peer: %v.", err)
	}

	return err
}

// createTapLink creates a tap link and attaches it to the bridge.
func (plugin *Plugin) createTapLink(bridgeName string, vethLinkName string, tapLinkName string, uid int) error {
	// Create the bridge link.
	la := netlink.NewLinkAttrs()
	la.Name = bridgeName
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

	// Connect veth link to the bridge.
	la = netlink.NewLinkAttrs()
	la.Name = vethLinkName
	vethLink := &netlink.Dummy{LinkAttrs: la}
	err = netlink.LinkSetMaster(vethLink, bridge)
	if err != nil {
		log.Errorf("Failed to set veth link master: %v", err)
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
		log.Errorf("Failed to add tap link: %v", err)
		return err
	}

	// Set tap link MTU.
	err = netlink.LinkSetMTU(tapLink, vpc.JumboFrameMTU)
	if err != nil {
		log.Errorf("Failed to set tap link MTU: %v", err)
		return err
	}

	// Set tap link ownership.
	log.Infof("Setting tap link owner to uid %d.", uid)
	fd := int(tapLink.Fds[0].Fd())
	err = unix.IoctlSetInt(fd, unix.TUNSETOWNER, uid)
	if err != nil {
		log.Errorf("Failed to set tap link owner: %v", err)
		return err
	}

	// Set tap link operational state up.
	log.Info("Setting tap link state up.")
	err = netlink.LinkSetUp(tapLink)
	if err != nil {
		log.Errorf("Failed to set tap link state: %v", err)
		return err
	}

	return nil
}
