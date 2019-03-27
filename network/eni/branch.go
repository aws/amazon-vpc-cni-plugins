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

// +build linux

package eni

import (
	"fmt"
	"net"

	"github.com/aws/amazon-vpc-cni-plugins/network/netlinkwrapper"
	"github.com/aws/amazon-vpc-cni-plugins/network/netwrapper"
	log "github.com/cihub/seelog"
	"github.com/vishvananda/netlink"
)

// Branch represents a VPC branch ENI.
type Branch struct {
	ENI
	isolationID int
	trunk       *Trunk
}

// NewBranch creates a new Branch object.
func NewBranch(trunk *Trunk, linkName string, macAddress net.HardwareAddr, isolationID int) (*Branch, error) {
	if trunk == nil {
		return nil, fmt.Errorf("Invalid trunk")
	}

	if isolationID == 0 {
		return nil, fmt.Errorf("Invalid isolationID")
	}

	branch := &Branch{
		ENI: ENI{
			linkName:       linkName,
			macAddress:     macAddress,
			netLinkWrapper: netlinkwrapper.NewNetLink(),
			netWrapper:     netwrapper.NewNet(),
		},
		isolationID: isolationID,
		trunk:       trunk,
	}

	return branch, nil
}

// NewBranchWithENI creates a new Branch object with given ENI and Trunk objects. This is used in testing.
func NewBranchWithENI(eni *ENI, trunk *Trunk, isolationID int) (*Branch, error) {
	if trunk == nil {
		return nil, fmt.Errorf("Invalid trunk")
	}

	if isolationID == 0 {
		return nil, fmt.Errorf("Invalid isolationID")
	}

	branch := &Branch{
		ENI:         *eni,
		isolationID: isolationID,
		trunk:       trunk,
	}

	return branch, nil
}

// AttachToLink attaches the branch ENI to a link.
func (branch *Branch) AttachToLink(setMACAddress bool) error {
	// Create the VLAN link.
	la := netlink.NewLinkAttrs()
	la.Name = branch.linkName
	la.ParentIndex = branch.trunk.linkIndex
	vlanLink := &netlink.Vlan{LinkAttrs: la, VlanId: branch.isolationID}

	log.Infof("Creating vlan link for branch [%s]: %+v", branch.linkName, vlanLink)
	if err := branch.netLinkWrapper.LinkAdd(vlanLink); err != nil {
		log.Errorf("Failed to add vlan link for branch [%s]: %v", branch.linkName, err)
		return err
	}

	branch.linkIndex = vlanLink.Index
	if setMACAddress && branch.macAddress != nil {
		// Set VLAN link MAC address to customer branch ENI MAC address.
		if err := branch.netLinkWrapper.LinkSetHardwareAddr(vlanLink, branch.macAddress); err != nil {
			log.Errorf("Failed to set MAC address for branch [%s] %v: %v",
				branch.linkName, branch.macAddress, err)
			return err
		}
		return nil
	}

	log.Debugf("Skip setting hardware address for branch [%s] overrideMAC: %t",
		branch.linkName, setMACAddress)
	return nil
}

// DetachFromLink detaches the branch ENI from a link.
func (branch *Branch) DetachFromLink() error {
	// Delete the VLAN link.
	la := netlink.NewLinkAttrs()
	la.Name = branch.linkName
	la.ParentIndex = branch.trunk.linkIndex
	vlanLink := &netlink.Vlan{LinkAttrs: la, VlanId: branch.isolationID}

	log.Infof("Deleting vlan link for branch [%s]: %+v", branch.linkName, vlanLink)
	err := branch.netLinkWrapper.LinkDel(vlanLink)
	if err != nil {
		log.Errorf("Failed to delete vlan link for branch [%s]: %v", branch.linkName, err)
		return err
	}

	branch.linkIndex = 0
	return nil
}
