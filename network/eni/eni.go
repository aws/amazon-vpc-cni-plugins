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
	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"

	log "github.com/cihub/seelog"
	"github.com/vishvananda/netlink"
)

// ENI represents a VPC elastic network interface.
type ENI struct {
	linkIndex  int
	linkName   string
	macAddress net.HardwareAddr
}

// NewENI creates a new ENI object. One of linkName or macAddress must be specified.
func NewENI(linkName string, macAddress net.HardwareAddr) (*ENI, error) {
	if linkName == "" && macAddress == nil {
		return nil, fmt.Errorf("missing linkName and macAddress")
	}

	eni := &ENI{
		linkName:   linkName,
		macAddress: macAddress,
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

// String returns a string representation of the ENI.
func (eni *ENI) String() string {
	return fmt.Sprintf("{linkName:%s macAddress:%s}", eni.linkName, eni.macAddress)
}

// Attach attaches the ENI to a link.
func (eni *ENI) Attach() error {
	var iface *net.Interface
	var err error

	if eni.linkName != "" {
		// Find the interface by name.
		iface, err = net.InterfaceByName(eni.linkName)
		if err != nil {
			log.Errorf("Failed to find interface with name %s: %v", eni.linkName, err)
			return err
		}
	} else {
		// Find the interface by MAC address.
		interfaces, err := net.Interfaces()
		if err != nil {
			return err
		}

		for _, i := range interfaces {
			if vpc.CompareMACAddress(i.HardwareAddr, eni.macAddress) {
				iface = &i
				break
			}
		}

		if iface == nil {
			log.Errorf("Failed to find interface with MAC address %s: %v", eni.macAddress, err)
			return fmt.Errorf("invalid MAC address")
		}
	}

	eni.linkIndex = iface.Index
	eni.linkName = iface.Name
	eni.macAddress = iface.HardwareAddr

	return nil
}

// Detach detaches the ENI from a link.
func (eni *ENI) Detach() error {
	eni.linkIndex = 0
	return nil
}

// SetName sets the name of the ENI.
func (eni *ENI) SetName(name string) error {
	la := netlink.NewLinkAttrs()
	la.Name = eni.linkName
	link := &netlink.Dummy{LinkAttrs: la}
	err := netlink.LinkSetName(link, name)

	if err != nil {
		return err
	}

	eni.linkName = name

	return nil
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

// SetMACAddress sets the MAC address of the ENI.
func (eni *ENI) SetMACAddress(address net.HardwareAddr) error {
	la := netlink.NewLinkAttrs()
	la.Name = eni.linkName
	link := &netlink.Dummy{LinkAttrs: la}

	err := netlink.LinkSetHardwareAddr(link, address)
	if err != nil {
		return err
	}

	eni.macAddress = address

	return nil
}

// SetIPAddress assigns the given IP address to the ENI.
func (eni *ENI) SetIPAddress(address *net.IPNet) error {
	la := netlink.NewLinkAttrs()
	la.Index = eni.linkIndex
	link := &netlink.Dummy{LinkAttrs: la}
	addr := &netlink.Addr{IPNet: address}

	err := netlink.AddrAdd(link, addr)
	if err != nil {
		return err
	}

	return nil
}
