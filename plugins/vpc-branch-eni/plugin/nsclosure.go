// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

	"github.com/aws/amazon-vpc-cni-plugins/network/eni"
	"github.com/aws/amazon-vpc-cni-plugins/network/imds"
	"github.com/aws/amazon-vpc-cni-plugins/network/netlinkwrapper"
	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-branch-eni/config"
	log "github.com/cihub/seelog"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// setupNamespaceClosureContext wraps the parameters and the method to configure the container's namespace.
type setupNamespaceClosureContext struct {
	branch     *eni.Branch
	branchName string
	ifName     string
	netConfig  *config.NetConfig
	netLink    netlinkwrapper.NetLink
	uid        int
}

// teardownNamespaceClosureContext wraps the parameters and the method to teardown the container's namespace.
type teardownNamespaceClosureContext struct {
	branchName    string
	netConfig     *config.NetConfig
	netLink       netlinkwrapper.NetLink
	tapBridgeName string
	tapLinkName   string
}

// newSetupNamespaceClosureContext creates a new setupNamespaceClosure object.
func newSetupNamespaceClosureContext(branch *eni.Branch, branchName string, ifName string, netConfig *config.NetConfig,
	netLink netlinkwrapper.NetLink, uid int) *setupNamespaceClosureContext {
	return &setupNamespaceClosureContext{
		branch:     branch,
		branchName: branchName,
		ifName:     ifName,
		netConfig:  netConfig,
		netLink:    netLink,
		uid:        uid,
	}
}

// newTeardownNamespaceClosureContext creates a new teardownNamespaceClosure object.
func newTeardownNamespaceClosureContext(branchName, tapBridgeName, tapLinkName string,
	netConfig *config.NetConfig, netLink netlinkwrapper.NetLink) *teardownNamespaceClosureContext {
	return &teardownNamespaceClosureContext{
		branchName:    branchName,
		netConfig:     netConfig,
		netLink:       netLink,
		tapBridgeName: tapBridgeName,
		tapLinkName:   tapLinkName,
	}
}

// run defines the closure to execute within the container's namespace to configure it appropriately.
func (closureContext *setupNamespaceClosureContext) run() error {
	var err error

	branch := closureContext.branch
	netConfig := closureContext.netConfig

	// Create the container-facing link based on the requested interface type.
	switch netConfig.InterfaceType {
	case config.IfTypeVLAN:
		// Container is running in a network namespace on this host.
		err = closureContext.createVLANLink(branch, closureContext.ifName, netConfig.BranchIPAddress, netConfig.BranchGatewayIPAddress)
	case config.IfTypeTAP:
		// Container is running in a VM.
		// Connect the branch ENI to a TAP link in the target network namespace.
		bridgeName := fmt.Sprintf(bridgeNameFormat, netConfig.BranchVlanID)
		err = closureContext.createTAPLink(bridgeName, closureContext.branchName, closureContext.ifName, closureContext.uid)
	case config.IfTypeMACVTAP:
		// Container is running in a VM.
		// Connect the branch ENI to a MACVTAP link in the target network namespace.
		err = closureContext.createMACVTAPLink(closureContext.ifName, branch.GetLinkIndex())
	}

	// Add a blackhole route for IMDS endpoint if required.
	if closureContext.netConfig.BlockIMDS {
		err = imds.BlockInstanceMetadataEndpoint(closureContext.netLink)
		if err != nil {
			return err
		}
	}

	// Set branch link operational state up. VLAN interfaces were already brought up above.
	if closureContext.netConfig.InterfaceType != config.IfTypeVLAN && err == nil {
		log.Infof("Setting branch link state up.")
		err = closureContext.branch.SetOpState(true)
		if err != nil {
			log.Errorf("Failed to set branch link %v state: %v.", closureContext.branch, err)
			return err
		}
	}

	return err
}

// run defines the closure to execute within the container's namespace to tear it down.
func (closureContext *teardownNamespaceClosureContext) run() error {
	netConfig := closureContext.netConfig

	var err error
	if netConfig.InterfaceType == config.IfTypeMACVTAP ||
		netConfig.InterfaceType == config.IfTypeTAP {
		// Delete the tap link.
		la := netlink.NewLinkAttrs()
		la.Name = closureContext.tapLinkName
		tapLink := &netlink.Tuntap{LinkAttrs: la}
		log.Infof("Deleting tap link: %v.", closureContext.tapLinkName)
		err = closureContext.netLink.LinkDel(tapLink)
		if err != nil {
			log.Errorf("Failed to delete tap link: %v.", err)
			return err
		}
	}

	// Delete the branch link.
	la := netlink.NewLinkAttrs()
	la.Name = closureContext.branchName
	branchLink := &netlink.Vlan{LinkAttrs: la}
	log.Infof("Deleting branch link: %v.", closureContext.branchName)
	err = closureContext.netLink.LinkDel(branchLink)
	if err != nil {
		log.Errorf("Failed to delete branch link: %v.", err)
		return err
	}

	if netConfig.InterfaceType == config.IfTypeTAP {
		// Delete the tap bridge.
		la = netlink.NewLinkAttrs()
		la.Name = closureContext.tapBridgeName
		tapBridge := &netlink.Bridge{LinkAttrs: la}
		log.Infof("Deleting tap bridge: %v.", closureContext.tapBridgeName)
		err = closureContext.netLink.LinkDel(tapBridge)
		if err != nil {
			log.Errorf("Failed to delete tap bridge: %v.", err)
			return err
		}
	}

	return nil
}

// createVLANLink creates a VLAN link in the target network namespace.
func (closureContext *setupNamespaceClosureContext) createVLANLink(branch *eni.Branch,
	linkName string, ipAddress *net.IPNet, gatewayIPAddress net.IP) error {
	// Rename the branch link to the requested interface name.
	log.Infof("Renaming branch link %v to %s.", branch, linkName)
	err := branch.SetLinkName(linkName)
	if err != nil {
		log.Errorf("Failed to rename branch link %v: %v.", branch, err)
		return err
	}

	// Set branch link operational state up.
	log.Infof("Setting branch link state up.")
	err = branch.SetOpState(true)
	if err != nil {
		log.Errorf("Failed to set branch link %v state: %v.", branch, err)
		return err
	}

	// Set branch IP address and default gateway if specified.
	if ipAddress != nil {
		// Assign the IP address.
		log.Infof("Assigning IP address %v to branch link.", ipAddress)
		err = branch.SetIPAddress(ipAddress)
		if err != nil {
			log.Errorf("Failed to assign IP address to branch link %v: %v.", branch, err)
			return err
		}

		// Add default route via branch link.
		route := &netlink.Route{
			Gw:        gatewayIPAddress,
			LinkIndex: branch.GetLinkIndex(),
		}
		log.Infof("Adding default IP route %+v.", route)
		err = closureContext.netLink.RouteAdd(route)
		if err != nil {
			log.Errorf("Failed to add IP route %+v via branch %v: %v.", route, branch, err)
			return err
		}
	}

	return nil
}

// createTAPLink creates a TAP link in the target network namespace.
func (closureContext *setupNamespaceClosureContext) createTAPLink(bridgeName string,
	branchName string, tapLinkName string, uid int) error {
	// Create the bridge link.
	la := netlink.NewLinkAttrs()
	la.Name = bridgeName
	la.MTU = vpc.JumboFrameMTU
	bridge := &netlink.Bridge{LinkAttrs: la}
	log.Infof("Creating bridge link %+v.", bridge)
	err := closureContext.netLink.LinkAdd(bridge)
	if err != nil {
		log.Errorf("Failed to create bridge link: %v", err)
		return err
	}

	// Set bridge link MTU.
	err = closureContext.netLink.LinkSetMTU(bridge, vpc.JumboFrameMTU)
	if err != nil {
		log.Errorf("Failed to set bridge link MTU: %v", err)
		return err
	}

	// Set bridge link operational state up.
	log.Info("Setting bridge link state up.")
	err = closureContext.netLink.LinkSetUp(bridge)
	if err != nil {
		log.Errorf("Failed to set bridge link state: %v", err)
		return err
	}

	// Connect branch link to the bridge.
	la = netlink.NewLinkAttrs()
	la.Name = branchName
	branchLink := &netlink.Dummy{LinkAttrs: la}
	err = closureContext.netLink.LinkSetMaster(branchLink, bridge)
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
	err = closureContext.netLink.LinkAdd(tapLink)
	if err != nil {
		log.Errorf("Failed to add TAP link: %v", err)
		return err
	}

	// Set TAP link MTU.
	err = closureContext.netLink.LinkSetMTU(tapLink, vpc.JumboFrameMTU)
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
	err = closureContext.netLink.LinkSetUp(tapLink)
	if err != nil {
		log.Errorf("Failed to set TAP link state: %v", err)
		return err
	}

	return nil
}

// createMACVTAPLink creates a MACVTAP link in the target network namespace.
func (closureContext *setupNamespaceClosureContext) createMACVTAPLink(linkName string, parentIndex int) error {
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
	err := closureContext.netLink.LinkAdd(macvtapLink)
	if err != nil {
		log.Errorf("Failed to add MACVTAP link: %v.", err)
		return err
	}

	// Set MACVTAP link operational state up.
	log.Infof("Setting MACVTAP link state up.")
	err = closureContext.netLink.LinkSetUp(macvtapLink)
	if err != nil {
		log.Errorf("Failed to set MACVTAP link state: %v.", err)
		return err
	}

	return nil
}
