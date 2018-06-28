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
	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-branch-eni/config"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniCurrent "github.com/containernetworking/cni/pkg/types/current"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// Name templates used for objects created by this plugin.
	branchLinkNameFormat = "%s.%s"
	bridgeNameFormat     = "tapbr%s"
)

// Add is the internal implementation of CNI ADD command.
func (plugin *Plugin) Add(args *cniSkel.CmdArgs) error {
	// Parse network configuration.
	netConfig, err := config.New(args)
	if err != nil {
		log.Errorf("Failed to parse netconfig from args: %v.", err)
		return err
	}

	log.Infof("Executing ADD with netconfig: %+v.", netConfig)

	// Derive names from CNI network config.
	// All fields have already been validated during parsing.
	branchName := fmt.Sprintf(branchLinkNameFormat, netConfig.TrunkName, netConfig.BranchVlanID)
	branchMACAddress, _ := net.ParseMAC(netConfig.BranchMACAddress)
	branchVlanID, _ := strconv.Atoi(netConfig.BranchVlanID)
	bridgeName := fmt.Sprintf(bridgeNameFormat, netConfig.BranchVlanID)
	ifName := args.IfName
	netnsName := args.Netns
	var uid int

	// Find the network namespace.
	log.Infof("Searching for netns %s.", netnsName)
	ns, err := netns.GetNetNSByName(netnsName)
	if err != nil {
		log.Errorf("Failed to find netns %s: %v.", netnsName, err)
		return err
	}

	if netConfig.InterfaceType == config.IfTypeVLAN {
		// Container is running on this host.
		// Return directly the branch ENI in the target network namespace.
		branchName = ifName
	} else if netConfig.InterfaceType == config.IfTypeTAP {
		// Container is running in a VM.
		// Connect the branch ENI to a TAP link in the target network namespace.

		// Lookup the user ID for TAP link.
		uid, err = plugin.CNIPlugin.LookupUser(netConfig.UserName)
		if err != nil {
			log.Errorf("Failed to lookup user %s: %v.", netConfig.UserName, err)
			return err
		}
		log.Infof("Lookup for username %s returned uid %d.", netConfig.UserName, uid)
	}

	// Create the trunk ENI.
	trunk, err := eni.NewTrunk(netConfig.TrunkName, eni.TrunkIsolationModeVLAN)
	if err != nil {
		log.Errorf("Failed to find trunk interface %s: %v.", netConfig.TrunkName, err)
		return err
	}

	// Create the branch ENI.
	branch, err := eni.NewBranch(trunk, branchName, branchMACAddress, branchVlanID)
	if err != nil {
		log.Errorf("Failed to create branch interface %s: %v.", branchName, err)
		return err
	}

	// Create a link for the branch ENI.
	log.Infof("Creating branch link %s", branchName)
	err = branch.AttachToLink()
	if err != nil {
		log.Errorf("Failed to attach branch interface %s: %v.", branchName, err)
		return err
	}

	// Move branch ENI to the network namespace.
	log.Infof("Moving branch link to network namespace.")
	err = branch.SetNetNS(ns)
	if err != nil {
		log.Errorf("Failed to move branch link: %v.", err)
		return err
	}

	// If the container is running in a VM, wrap the branch link with a MACVTAP or TAP link.
	if netConfig.InterfaceType != config.IfTypeVLAN {
		// In target network namespace...
		err = ns.Run(func() error {
			if netConfig.InterfaceType == config.IfTypeTAP {
				err = plugin.createTAPLink(bridgeName, branchName, ifName, uid)
			} else {
				err = plugin.createMACVTAPLink(ifName, branch.GetLinkIndex())
			}
			return err
		})

		if err != nil {
			log.Errorf("Failed to create TAP link: %v.", err)
			return err
		}
	}

	// Set branch link operational state up.
	log.Infof("Setting branch link state up.")
	err = ns.Run(func() error {
		return branch.SetOpState(true)
	})
	if err != nil {
		log.Errorf("Failed to set branch link state: %v.", err)
		return err
	}

	// Generate CNI result.
	// IP addresses, routes and DNS are configured by VPC DHCP servers.
	result := &cniCurrent.Result{
		Interfaces: []*cniCurrent.Interface{
			{
				Name:    ifName,
				Mac:     branchMACAddress.String(),
				Sandbox: netnsName,
			},
		},
	}

	log.Infof("Writing CNI result to stdout: %+v", result)

	return cniTypes.PrintResult(result, netConfig.CNIVersion)
}

// Del is the internal implementation of CNI DEL command.
func (plugin *Plugin) Del(args *cniSkel.CmdArgs) error {
	// Parse network configuration.
	netConfig, err := config.New(args)
	if err != nil {
		log.Errorf("Failed to parse netconfig from args: %v.", err)
		return err
	}

	log.Infof("Executing DEL with netconfig: %+v.", netConfig)

	// Derive names from CNI network config.
	branchName := fmt.Sprintf(branchLinkNameFormat, netConfig.TrunkName, netConfig.BranchVlanID)
	tapBridgeName := fmt.Sprintf(bridgeNameFormat, netConfig.BranchVlanID)
	tapLinkName := args.IfName
	netnsName := args.Netns

	// Search for the target network namespace.
	netns, err := netns.GetNetNSByName(netnsName)
	if err == nil {
		// In target network namespace...
		err = netns.Run(func() error {
			if netConfig.InterfaceType == config.IfTypeMACVTAP ||
				netConfig.InterfaceType == config.IfTypeTAP {
				// Delete the tap link.
				la := netlink.NewLinkAttrs()
				la.Name = tapLinkName
				tapLink := &netlink.Tuntap{LinkAttrs: la}
				log.Infof("Deleting tap link: %v.", tapLinkName)
				err = netlink.LinkDel(tapLink)
				if err != nil {
					log.Errorf("Failed to delete tap link: %v.", err)
				}
			}

			// Delete the branch link.
			la := netlink.NewLinkAttrs()
			la.Name = branchName
			branchLink := &netlink.Vlan{LinkAttrs: la}
			log.Infof("Deleting branch link: %v.", branchName)
			err = netlink.LinkDel(branchLink)
			if err != nil {
				log.Errorf("Failed to delete branch link: %v.", err)
			}

			if netConfig.InterfaceType == config.IfTypeTAP {
				// Delete the tap bridge.
				la = netlink.NewLinkAttrs()
				la.Name = tapBridgeName
				tapBridge := &netlink.Bridge{LinkAttrs: la}
				log.Infof("Deleting tap bridge: %v.", tapBridgeName)
				err = netlink.LinkDel(tapBridge)
				if err != nil {
					log.Errorf("Failed to delete tap bridge: %v.", err)
				}
			}

			return nil
		})
	} else {
		// Log and ignore the failure. DEL can be called multiple times and thus must be idempotent.
		log.Errorf("Failed to find netns %s, ignoring: %v.", netnsName, err)
	}

	return nil
}

// createTAPLink creates a TAP link in the target network namespace.
func (plugin *Plugin) createTAPLink(bridgeName string, branchName string, tapLinkName string, uid int) error {
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

	// Set bridge link operational state up.
	log.Info("Setting bridge link state up.")
	err = netlink.LinkSetUp(bridge)
	if err != nil {
		log.Errorf("Failed to set bridge link state: %v", err)
		return err
	}

	// Connect branch link to the bridge.
	la = netlink.NewLinkAttrs()
	la.Name = branchName
	branchLink := &netlink.Dummy{LinkAttrs: la}
	err = netlink.LinkSetMaster(branchLink, bridge)
	if err != nil {
		log.Errorf("Failed to set branch link master: %v", err)
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
	log.Info("Setting TAP link state up.")
	err = netlink.LinkSetUp(tapLink)
	if err != nil {
		log.Errorf("Failed to set TAP link state: %v", err)
		return err
	}

	return nil
}

// createMACVTAPLink creates a MACVTAP link in the target network namespace.
func (plugin *Plugin) createMACVTAPLink(linkName string, parentIndex int) error {
	// Create a MACVTAP link attached to the parent link.
	la := netlink.NewLinkAttrs()
	la.Name = linkName
	la.ParentIndex = parentIndex
	macvtapLink := &netlink.Macvtap{
		netlink.Macvlan{
			LinkAttrs: la,
			Mode:      netlink.MACVLAN_MODE_PASSTHRU,
		},
	}

	log.Infof("Creating MACVTAP link %+v.", macvtapLink)
	err := netlink.LinkAdd(macvtapLink)
	if err != nil {
		log.Errorf("Failed to add MACVTAP link: %v.", err)
		return err
	}

	// Set MACVTAP link operational state up.
	log.Infof("Setting MACVTAP link state up.")
	err = netlink.LinkSetUp(macvtapLink)
	if err != nil {
		log.Errorf("Failed to set MACVTAP link state: %v.", err)
		return err
	}

	return nil
}
