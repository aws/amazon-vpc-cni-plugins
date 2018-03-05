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

package eni

import (
	"fmt"
	"net"

	"github.com/aws/amazon-vpc-cni-plugins/network/netns"

	"github.com/vishvananda/netlink"
)

// ENI represents a VPC elastic network interface.
type ENI struct {
	linkIndex  int
	linkName   string
	macAddress net.HardwareAddr
}

// NewENI creates a new ENI object.
func NewENI(linkName string) (*ENI, error) {
	eni := &ENI{
		linkName: linkName,
	}

	return eni, nil
}

// GetLinkIndex returns the local interface index of the ENI.
func (eni *ENI) GetLinkIndex() int {
	return eni.linkIndex
}

// GetLinkName returns the local interface name of the ENI.
func (eni *ENI) GetLinkName() string {
	return eni.linkName
}

// SetOpState sets the operational state of the ENI.
func (eni *ENI) SetOpState(up bool) error {
	var err error

	la := netlink.NewLinkAttrs()
	la.Name = eni.linkName
	link := &netlink.Dummy{LinkAttrs: la}

	if up {
		err = netlink.LinkSetUp(link)
	} else {
		err = netlink.LinkSetDown(link)
	}

	return err
}

// SetNetNS sets the network namespace of the ENI.
func (eni *ENI) SetNetNS(ns netns.NetNS) error {
	la := netlink.NewLinkAttrs()
	la.Name = eni.linkName
	link := &netlink.Dummy{LinkAttrs: la}
	err := netlink.LinkSetNsFd(link, int(ns.GetFd()))

	return err
}

// Attach attaches the ENI to a link.
func (eni *ENI) Attach() error {
	iface, err := net.InterfaceByName(eni.linkName)
	if err != nil {
		return fmt.Errorf("Invalid link name")
	}

	eni.linkIndex = iface.Index

	return nil
}

// Detach detaches the ENI from a link.
func (eni *ENI) Detach() error {
	eni.linkIndex = 0
	return nil
}
