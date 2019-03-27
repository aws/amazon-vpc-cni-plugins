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

	"github.com/aws/amazon-vpc-cni-plugins/network/eni"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-branch-eni/config"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypesCurrent "github.com/containernetworking/cni/pkg/types/current"
)

const (
	// Name templates used for objects created by this plugin.
	branchLinkNameFormat = "%s.%d"
	bridgeNameFormat     = "tapbr%d"
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

	// Find the network namespace.
	log.Infof("Searching for netns %s.", args.Netns)
	ns, err := plugin.NetNSProvider.GetNetNS(args.Netns)
	if err != nil {
		log.Errorf("Failed to find netns %s: %v.", args.Netns, err)
		return err
	}

	// Lookup the user ID for TAP link ownership.
	var uid int
	if netConfig.InterfaceType == config.IfTypeTAP {
		uid, err = plugin.LookupUser(netConfig.UserName)
		if err != nil {
			log.Errorf("Failed to lookup user %s: %v.", netConfig.UserName, err)
			return err
		}
		log.Infof("Lookup for username %s returned uid %d.", netConfig.UserName, uid)
	}

	// Create the trunk ENI.
	trunk, err := plugin.ENIWrapper.NewTrunk(netConfig.TrunkName, netConfig.TrunkMACAddress, eni.TrunkIsolationModeVLAN)
	if err != nil {
		log.Errorf("Failed to find trunk interface %s: %v.", netConfig.TrunkName, err)
		return err
	}

	// Create the branch ENI.
	branchName := fmt.Sprintf(branchLinkNameFormat, trunk.GetLinkName(), netConfig.BranchVlanID)
	branch, err := plugin.ENIWrapper.NewBranch(trunk, branchName, netConfig.BranchMACAddress, netConfig.BranchVlanID)
	if err != nil {
		log.Errorf("Failed to create branch interface %s: %v.", branchName, err)
		return err
	}

	// Create a link for the branch ENI.
	log.Infof("Creating branch link %s.", branchName)
	overrideMAC := netConfig.InterfaceType == config.IfTypeVLAN
	err = branch.AttachToLink(overrideMAC)
	if err != nil {
		log.Errorf("Failed to attach branch interface %s: %v.", branchName, err)
		return err
	}

	// Move branch ENI to the network namespace.
	log.Infof("Moving branch link %s to netns %s.", branch, args.Netns)
	err = branch.SetNetNS(ns)
	if err != nil {
		log.Errorf("Failed to move branch link: %v.", err)
		return err
	}

	closureContext := newSetupNamespaceClosureContext(branch, branchName, args.IfName, netConfig,
		plugin.NetLinkWrapper, uid)
	// Complete the remaining setup in target network namespace.
	err = ns.Run(closureContext.run)

	if err != nil {
		log.Errorf("Failed to setup the link: %v.", err)
		return err
	}

	// Generate CNI result.
	// IP addresses, routes and DNS are configured by VPC DHCP servers.
	result := &cniTypesCurrent.Result{
		Interfaces: []*cniTypesCurrent.Interface{
			{
				Name:    args.IfName,
				Mac:     netConfig.BranchMACAddress.String(),
				Sandbox: args.Netns,
			},
		},
	}

	log.Infof("Writing CNI result to stdout: %+v", result)

	return plugin.CNIWrapper.PrintResult(result, netConfig.CNIVersion)
}

// Del is the internal implementation of CNI DEL command.
// CNI DEL command can be called by the orchestrator agent multiple times for the same interface,
// and thus must be best-effort and idempotent.
func (plugin *Plugin) Del(args *cniSkel.CmdArgs) error {
	// Parse network configuration.
	netConfig, err := config.New(args)
	if err != nil {
		log.Errorf("Failed to parse netconfig from args: %v.", err)
		return err
	}

	log.Infof("Executing DEL with netconfig: %+v.", netConfig)

	// Derive names from CNI network config.
	var branchName string
	if netConfig.InterfaceType == config.IfTypeVLAN {
		branchName = args.IfName
	} else {
		// Find the trunk link name if not known.
		if netConfig.TrunkName == "" {
			trunk, err := plugin.ENIWrapper.NewTrunk("", netConfig.TrunkMACAddress, eni.TrunkIsolationModeVLAN)
			if err != nil {
				// Log and ignore the failure.
				log.Errorf("Failed to find trunk with MAC address %v: %v.", netConfig.TrunkMACAddress, err)
				return nil
			}
			netConfig.TrunkName = trunk.GetLinkName()
		}
		branchName = fmt.Sprintf(branchLinkNameFormat, netConfig.TrunkName, netConfig.BranchVlanID)
	}
	tapBridgeName := fmt.Sprintf(bridgeNameFormat, netConfig.BranchVlanID)
	tapLinkName := args.IfName

	// Search for the target network namespace.
	netns, err := plugin.NetNSProvider.GetNetNS(args.Netns)
	if err == nil {
		closureContext := newTeardownNamespaceClosureContext(branchName, tapBridgeName, tapLinkName, netConfig, plugin.NetLinkWrapper)
		// In target network namespace...
		err = netns.Run(closureContext.run)
	} else {
		// Log and ignore the failure. DEL can be called multiple times and thus must be idempotent.
		log.Errorf("Failed to find netns %s, ignoring: %v.", args.Netns, err)
	}

	return nil
}
