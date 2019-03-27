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
	"net"

	"github.com/aws/amazon-vpc-cni-plugins/network/netns"

	"github.com/vishvananda/netlink"
)

// SetLinkName sets the name of the ENI.
func (eni *ENI) SetLinkName(name string) error {
	la := netlink.NewLinkAttrs()
	la.Name = eni.linkName
	link := &netlink.Dummy{LinkAttrs: la}
	err := eni.netLinkWrapper.LinkSetName(link, name)

	if err != nil {
		return err
	}

	eni.linkName = name

	return nil
}

// SetLinkMTU sets the maximum transmission unit of the ENI.
func (eni *ENI) SetLinkMTU(mtu uint) error {
	la := netlink.NewLinkAttrs()
	la.Name = eni.linkName
	link := &netlink.Dummy{LinkAttrs: la}
	return eni.netLinkWrapper.LinkSetMTU(link, int(mtu))
}

// SetOpState sets the operational state of the ENI.
func (eni *ENI) SetOpState(up bool) error {
	var err error

	la := netlink.NewLinkAttrs()
	la.Name = eni.linkName
	link := &netlink.Dummy{LinkAttrs: la}

	if up {
		err = eni.netLinkWrapper.LinkSetUp(link)
	} else {
		err = eni.netLinkWrapper.LinkSetDown(link)
	}

	return err
}

// SetNetNS sets the network namespace of the ENI.
func (eni *ENI) SetNetNS(ns netns.NetNS) error {
	la := netlink.NewLinkAttrs()
	la.Name = eni.linkName
	link := &netlink.Dummy{LinkAttrs: la}
	return eni.netLinkWrapper.LinkSetNsFd(link, int(ns.GetFd()))
}

// SetMACAddress sets the MAC address of the ENI.
func (eni *ENI) SetMACAddress(address net.HardwareAddr) error {
	la := netlink.NewLinkAttrs()
	la.Name = eni.linkName
	link := &netlink.Dummy{LinkAttrs: la}

	err := eni.netLinkWrapper.LinkSetHardwareAddr(link, address)
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

	err := eni.netLinkWrapper.AddrAdd(link, addr)
	if err != nil {
		return err
	}

	return nil
}
