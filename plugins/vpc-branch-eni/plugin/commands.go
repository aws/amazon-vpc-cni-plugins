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
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-branch-eni/config"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniCurrent "github.com/containernetworking/cni/pkg/types/current"
	"github.com/vishvananda/netlink"
)

const (
	netNSNameFormat       = "vm%s_net"
	branchLinkNameFormat  = "%s.%s"
	macvtapLinkNameFormat = "macvtap%s"
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

	var netnsName string
	var ns netns.NetNS
	var hwVirtualized bool
	var ifName string

	// Find or create the network namespace.
	if args.Netns == "null" {
		// Container runs hardware virtualized.
		// The target network namespace is inside a VM.
		hwVirtualized = true
		netnsName = fmt.Sprintf(netNSNameFormat, netConfig.BranchVlanID)
		log.Infof("Creating netns %s.", netnsName)
		ns, err = netns.NewNetNS(netnsName)
	} else {
		// Container runs OS virtualized.
		// The target network namespace is on this host.
		hwVirtualized = false
		ifName = branchName
		netnsName = args.Netns
		log.Infof("Searching for netns %s.", netnsName)
		ns, err = netns.GetNetNSByName(netnsName)
	}

	if err != nil {
		log.Errorf("Failed to find or create netns %s: %v.", netnsName, err)
		return err
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

	// If the container is running in a VM, wrap the branch link with a MACVTAP link.
	if hwVirtualized {
		// In target network namespace...
		err = ns.Run(func() error {
			// Create a MACVTAP link and attach it on top of the branch link.
			ifName = fmt.Sprintf(macvtapLinkNameFormat, netConfig.BranchVlanID)
			la := netlink.NewLinkAttrs()
			la.Name = ifName
			la.ParentIndex = branch.GetLinkIndex()
			macvtapLink := &netlink.Macvtap{
				netlink.Macvlan{
					LinkAttrs: la,
					Mode:      netlink.MACVLAN_MODE_PASSTHRU,
				},
			}

			log.Infof("Creating macvtap link %+v.", macvtapLink)
			err = netlink.LinkAdd(macvtapLink)
			if err != nil {
				log.Errorf("Failed to add macvtap link: %v.", err)
				return err
			}

			// Set MACVTAP link operational state up.
			log.Infof("Setting macvtap link state up.")
			return netlink.LinkSetUp(macvtapLink)
		})

		if err != nil {
			log.Errorf("Failed to set macvtap link state: %v.", err)
			return err
		}
	}

	// Set branch link operational state up.
	log.Infof("Setting branch link state up.")
	err = ns.Run(func() error {
		return branch.SetOpState(true)
	})
	if err != nil {
		log.Errorf("Failed to set vlan link state: %v.", err)
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
	netnsName := fmt.Sprintf(netNSNameFormat, netConfig.BranchVlanID)

	// Find the network namespace.
	log.Infof("Deleting netns %s.", netnsName)
	ns, err := netns.GetNetNSByName(netnsName)
	if err != nil {
		log.Errorf("Failed to find netns: %v.", err)
		return err
	}

	// Delete the network namespace and thereby all virtual interfaces in it.
	err = ns.Close()
	if err != nil {
		log.Errorf("Failed to delete netns: %v.", err)
		return err
	}

	return nil
}
