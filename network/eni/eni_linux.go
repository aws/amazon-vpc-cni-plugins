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
	err := netlink.LinkSetName(link, name)

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
	return netlink.LinkSetMTU(link, int(mtu))
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
// If ns argument is nil, the ENI is reset to the host network namespace.
func (eni *ENI) SetNetNS(ns netns.NetNS) error {
	la := netlink.NewLinkAttrs()
	la.Name = eni.linkName
	link := &netlink.Dummy{LinkAttrs: la}
	if ns != nil {
		// Move the ENI to the given network namespace.
		return netlink.LinkSetNsFd(link, int(ns.GetFd()))
	} else {
		// PID 1 init is running in the host network namespace.
		return netlink.LinkSetNsPid(link, 1)
	}
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

// AddIPAddress assigns the given IP address to the ENI.
func (eni *ENI) AddIPAddress(address *net.IPNet) error {
	la := netlink.NewLinkAttrs()
	la.Index = eni.linkIndex
	link := &netlink.Dummy{LinkAttrs: la}
	addr := &netlink.Addr{IPNet: address}

	return netlink.AddrAdd(link, addr)
}

// DeleteIPAddress deletes the given IP address from the ENI.
func (eni *ENI) DeleteIPAddress(address *net.IPNet) error {
	la := netlink.NewLinkAttrs()
	la.Index = eni.linkIndex
	link := &netlink.Dummy{LinkAttrs: la}
	addr := &netlink.Addr{IPNet: address}

	return netlink.AddrDel(link, addr)
}
