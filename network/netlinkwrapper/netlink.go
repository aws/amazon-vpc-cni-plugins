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

package netlinkwrapper

import (
	"net"

	"github.com/vishvananda/netlink"
)

// NetLink wraps the methods of vishvananda/netlink package to be used in testing.
type NetLink interface {
	// AddrAdd will add an IP address to a link device.
	// Equivalent to: `ip addr add $addr dev $link`
	AddrAdd(link netlink.Link, addr *netlink.Addr) error
	// LinkAdd adds a new link device. The type and features of the device
	// are taken from the parameters in the link object.
	// Equivalent to: `ip link add $link`
	LinkAdd(link netlink.Link) error
	// LinkDel deletes link device. Either Index or Name must be set in
	// the link object for it to be deleted. The other values are ignored.
	// Equivalent to: `ip link del $link`
	LinkDel(link netlink.Link) error
	// LinkSetHardwareAddr sets the hardware address of the link device.
	// Equivalent to: `ip link set $link address $hwaddr`
	LinkSetHardwareAddr(link netlink.Link, hwaddr net.HardwareAddr) error
	// LinkSetMaster sets the master of the link device.
	// Equivalent to: `ip link set $link master $master`
	LinkSetMaster(link netlink.Link, master *netlink.Bridge) error
	// LinkSetMTU sets the mtu of the link device.
	// Equivalent to: `ip link set $link mtu $mtu`
	LinkSetMTU(link netlink.Link, mtu int) error
	// LinkSetName sets the name of the link device.
	// Equivalent to: `ip link set $link name $name`
	LinkSetName(link netlink.Link, name string) error
	// LinkSetNsFd puts the device into a new network namespace. The
	// fd must be an open file descriptor to a network namespace.
	// Similar to: `ip link set $link netns $ns`
	LinkSetNsFd(link netlink.Link, fd int) error
	// LinkSetUp enables the link device.
	// Equivalent to: `ip link set $link up`
	LinkSetUp(link netlink.Link) error
	// LinkSetDown disables link device.
	// Equivalent to: `ip link set $link down`
	LinkSetDown(link netlink.Link) error
	// RouteAdd will add a route to the system.
	// Equivalent to: `ip route add $route`
	RouteAdd(route *netlink.Route) error
}

type netLink struct {
}

// NewNetLink creates a new NetLink object.
func NewNetLink() NetLink {
	return &netLink{}
}

func (*netLink) AddrAdd(link netlink.Link, addr *netlink.Addr) error {
	return netlink.AddrAdd(link, addr)
}

func (*netLink) LinkAdd(link netlink.Link) error {
	return netlink.LinkAdd(link)
}

func (*netLink) LinkDel(link netlink.Link) error {
	return netlink.LinkDel(link)
}

func (*netLink) LinkSetHardwareAddr(link netlink.Link, hwaddr net.HardwareAddr) error {
	return netlink.LinkSetHardwareAddr(link, hwaddr)
}

func (*netLink) LinkSetMaster(link netlink.Link, master *netlink.Bridge) error {
	return netlink.LinkSetMaster(link, master)
}

func (*netLink) LinkSetMTU(link netlink.Link, mtu int) error {
	return netlink.LinkSetMTU(link, mtu)
}

func (*netLink) LinkSetName(link netlink.Link, name string) error {
	return netlink.LinkSetName(link, name)
}

func (*netLink) LinkSetNsFd(link netlink.Link, fd int) error {
	return netlink.LinkSetNsFd(link, fd)
}

func (*netLink) LinkSetUp(link netlink.Link) error {
	return netlink.LinkSetUp(link)
}

func (*netLink) LinkSetDown(link netlink.Link) error {
	return netlink.LinkSetDown(link)
}

func (*netLink) RouteAdd(route *netlink.Route) error {
	return netlink.RouteAdd(route)
}
