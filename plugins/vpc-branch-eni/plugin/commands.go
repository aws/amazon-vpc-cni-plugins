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
	"os"

	"github.com/aws/amazon-vpc-cni-plugins/network/eni"
	"github.com/aws/amazon-vpc-cni-plugins/network/imds"
	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-branch-eni/config"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesCurrent "github.com/containernetworking/cni/pkg/types/100"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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
	ns, err := netns.GetNetNS(args.Netns)
	if err != nil {
		log.Errorf("Failed to find netns %s: %v.", args.Netns, err)
		return err
	}

	// Create the trunk ENI.
	trunk, err := eni.NewTrunk(netConfig.TrunkName, netConfig.TrunkMACAddress, eni.TrunkIsolationModeVLAN)
	if err != nil {
		log.Errorf("Failed to find trunk interface %s: %v.", netConfig.TrunkName, err)
		return err
	}

	// Bring up the trunk ENI.
	err = trunk.SetOpState(true)
	if err != nil {
		log.Errorf("Failed to bring up trunk interface %s: %v", netConfig.TrunkName, err)
		return err
	}

	// Create the branch ENI.
	branchName := fmt.Sprintf(branchLinkNameFormat, trunk.GetLinkName(), netConfig.BranchVlanID)
	branch, err := eni.NewBranch(trunk, branchName, netConfig.BranchMACAddress, netConfig.BranchVlanID)
	if err != nil {
		log.Errorf("Failed to create branch interface %s: %v.", branchName, err)
		return err
	}

	// Create a link for the branch ENI.
	log.Infof("Creating branch link %s.", branchName)
	overrideMAC := netConfig.InterfaceType == config.IfTypeVLAN
	err = branch.AttachToLink(overrideMAC)
	if err != nil {
		if os.IsExist(err) {
			// If the branch link already exists, it may have been created in a previous invocation
			// of this plugin. Look for it in the target network namespace and reset it.
			err = ns.Run(func() error {
				err := branch.ENI.AttachToLink()
				if err != nil {
					return err
				}

				for _, ipAddr := range netConfig.IPAddresses {
					err = branch.DeleteIPAddress(&ipAddr)
					if os.IsNotExist(err) {
						err = nil
					} else if err != nil {
						log.Errorf("Failed to reset branch link: %v", err)
					}
				}
				return err
			})
		}
		if err != nil {
			log.Errorf("Failed to attach branch interface %s: %v.", branchName, err)
			return err
		}
	} else {
		// Move branch ENI to the network namespace.
		log.Infof("Moving branch link %s to netns %s.", branch, args.Netns)
		err = branch.SetNetNS(ns)
		if err != nil {
			log.Errorf("Failed to move branch link: %v.", err)
			return err
		}
	}

	// Complete the remaining setup in target network namespace.
	err = ns.Run(func() error {
		var err error

		// Create the container-facing link based on the requested interface type.
		switch netConfig.InterfaceType {
		case config.IfTypeVLAN:
			// Container is running in a network namespace on this host.
			err = plugin.createVLANLink(branch, args.IfName, netConfig.IPAddresses, netConfig.GatewayIPAddresses)
		case config.IfTypeTAP:
			// Container is running in a VM.
			// Connect the branch ENI to a TAP link in the target network namespace.
			bridgeName := fmt.Sprintf(bridgeNameFormat, netConfig.BranchVlanID)
			err = plugin.createTAPLink(branch, bridgeName, args.IfName, netConfig.Tap)
		case config.IfTypeMACVTAP:
			// Container is running in a VM.
			// Connect the branch ENI to a MACVTAP link in the target network namespace.
			err = plugin.createMACVTAPLink(args.IfName, branch.GetLinkIndex())
		}

		// Add a blackhole route for IMDS endpoint if required.
		if netConfig.BlockIMDS {
			err = imds.BlockInstanceMetadataEndpoint()
			if err != nil {
				return err
			}
		}

		// Set branch link operational state up. VLAN interfaces were already brought up above.
		if netConfig.InterfaceType != config.IfTypeVLAN && err == nil {
			log.Infof("Setting branch link state up.")
			err = branch.SetOpState(true)
			if err != nil {
				log.Errorf("Failed to set branch link %v state: %v.", branch, err)
				return err
			}
		}

		return err
	})

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

	return cniTypes.PrintResult(result, netConfig.CNIVersion)
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
			trunk, err := eni.NewTrunk("", netConfig.TrunkMACAddress, eni.TrunkIsolationModeVLAN)
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
	netns, err := netns.GetNetNS(args.Netns)
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
		if err != nil {
			log.Errorf("Failed to set netns %s, ignoring: %v.", args.Netns, err)
		}
	} else {
		// Log and ignore the failure. DEL can be called multiple times and thus must be idempotent.
		log.Errorf("Failed to find netns %s, ignoring: %v.", args.Netns, err)
	}

	return nil
}

// createVLANLink creates a VLAN link in the target network namespace.
func (plugin *Plugin) createVLANLink(
	branch *eni.Branch,
	linkName string,
	ipAddresses []net.IPNet,
	gatewayIPAddresses []net.IP) error {

	// Rename the branch link to the requested interface name.
	if branch.GetLinkName() != linkName {
		log.Infof("Renaming branch link %v to %s.", branch, linkName)
		err := branch.SetLinkName(linkName)
		if err != nil {
			log.Errorf("Failed to rename branch link %v: %v.", branch, err)
			return err
		}
	}

	// Set branch link operational state up.
	err := branch.SetOpState(true)
	if err != nil {
		log.Errorf("Failed to set branch link %v state: %v.", branch, err)
		return err
	}

	// Set branch IP addresses if specified.
	for _, ipAddress := range ipAddresses {
		// Assign the IP address.
		log.Infof("Assigning IP address %v to branch link.", ipAddress)
		err = branch.AddIPAddress(&ipAddress)
		if err != nil {
			log.Errorf("Failed to assign IP address to branch link %v: %v.", branch, err)
			return err
		}
	}

	// Set default gateways if specified.
	for _, gatewayIPAddress := range gatewayIPAddresses {
		// Add default route via branch link.
		route := &netlink.Route{
			Gw:        gatewayIPAddress,
			LinkIndex: branch.GetLinkIndex(),
		}
		log.Infof("Adding default IP route %+v.", route)
		err = netlink.RouteAdd(route)
		if err != nil {
			log.Errorf("Failed to add IP route %+v via branch %v: %v.", route, branch, err)
			return err
		}
	}

	return nil
}

// createTAPLink creates a TAP link in the target network namespace.
func (plugin *Plugin) createTAPLink(
	branch *eni.Branch,
	bridgeName string,
	tapLinkName string,
	tapCfg *config.TAPConfig) error {

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

	// In TAP mode, the branch ENI's MAC address is used exclusively by the consumer of the TAP
	// interface (e.g. a VM), so it shouldn't be assigned to the branch link itself. However, this
	// can happen if the branch link is being reused between successive invocations of the plugin.
	// Overriding the branch link's MAC address with that of the bridge prevents that.
	bridgeLink, err := netlink.LinkByIndex(bridge.Index)
	if err != nil {
		log.Errorf("Failed to find bridge link: %v", err)
		return err
	}

	err = branch.SetMACAddress(bridgeLink.Attrs().HardwareAddr)
	if err != nil {
		log.Errorf("Failed to set branch link MAC address: %v.", err)
		return err
	}

	// Set bridge link operational state up.
	err = netlink.LinkSetUp(bridge)
	if err != nil {
		log.Errorf("Failed to set bridge link state: %v", err)
		return err
	}

	// Connect branch link to the bridge.
	la = netlink.NewLinkAttrs()
	la.Name = branch.GetLinkName()
	branchLink := &netlink.Dummy{LinkAttrs: la}
	err = netlink.LinkSetMaster(branchLink, bridge)
	if err != nil {
		log.Errorf("Failed to set branch link master: %v", err)
		return err
	}

	// Create the TAP link.
	// Parse headers added by virtio_net implementation.
	la = netlink.NewLinkAttrs()
	la.Name = tapLinkName
	la.MasterIndex = bridge.Index
	la.MTU = vpc.JumboFrameMTU
	tapLink := &netlink.Tuntap{
		LinkAttrs: la,
		Mode:      netlink.TUNTAP_MODE_TAP,
		Flags:     netlink.TUNTAP_VNET_HDR,
		Queues:    tapCfg.Queues,
	}

	if tapCfg.Queues == 1 {
		tapLink.Flags |= netlink.TUNTAP_ONE_QUEUE
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
	log.Infof("Setting TAP link owner to UID %d and GID %d.", tapCfg.Uid, tapCfg.Gid)
	for _, tapFd := range tapLink.Fds {
		fd := int(tapFd.Fd())

		err = unix.IoctlSetInt(fd, unix.TUNSETOWNER, tapCfg.Uid)
		if err != nil {
			log.Errorf("Failed to set TAP link UID: %v", err)
			return err
		}
		err = unix.IoctlSetInt(fd, unix.TUNSETGROUP, tapCfg.Gid)
		if err != nil {
			log.Errorf("Failed to set TAP link GID: %v", err)
			return err
		}

		tapFd.Close()
	}

	// Set TAP link operational state up.
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
		Macvlan: netlink.Macvlan{
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
	err = netlink.LinkSetUp(macvtapLink)
	if err != nil {
		log.Errorf("Failed to set MACVTAP link state: %v.", err)
		return err
	}

	return nil
}
