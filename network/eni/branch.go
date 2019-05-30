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
			linkName:   linkName,
			macAddress: macAddress,
		},
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
	if setMACAddress && branch.macAddress != nil {
		// Set VLAN link MAC address to customer branch ENI MAC address.
		la.HardwareAddr = branch.macAddress
	} else {
		log.Debugf("Skip setting hardware address for branch [%s] overrideMAC: %t",
			branch.linkName, setMACAddress)
	}

	vlanLink := &netlink.Vlan{LinkAttrs: la, VlanId: branch.isolationID}

	log.Infof("Creating vlan link for branch [%s]: %+v", branch.linkName, vlanLink)
	if err := netlink.LinkAdd(vlanLink); err != nil {
		log.Errorf("Failed to add vlan link for branch [%s]: %v", branch.linkName, err)
		return err
	}

	branch.linkIndex = vlanLink.Index
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
	err := netlink.LinkDel(vlanLink)
	if err != nil {
		log.Errorf("Failed to delete vlan link for branch [%s]: %v", branch.linkName, err)
		return err
	}

	branch.linkIndex = 0
	return nil
}
