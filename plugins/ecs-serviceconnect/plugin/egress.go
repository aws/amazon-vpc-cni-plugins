// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
	"net"
	"strconv"

	"github.com/aws/amazon-vpc-cni-plugins/plugins/ecs-serviceconnect/config"

	log "github.com/cihub/seelog"
	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// Egress iptables chains created for ECS Service Connect rules.
	egressTProxyChain = "ECS_SERVICE_CONNECT_DIVERT"
	//Constants for handling Tproxy
	tproxyRouteTable  = 100
	tproxyRouteMarker = 1
	tproxyMark        = "0x1/0x1"
)

// setupEgressRules sets Egress port redirection rules in the network namespace.
func (plugin *Plugin) setupEgressRules(
	iptable *iptables.IPTables,
	proto iptables.Protocol,
	conf *config.NetConfig) error {
	switch conf.EgressRedirectMode {
	case config.NAT:
		// Redirect traffic in the CIDR block to the egress port.
		if conf.EgressPort != 0 {
			return plugin.redirectCIDRTrafficByNAT(iptable, plugin.getCidr(proto, conf),
				strconv.Itoa(conf.EgressPort))
		}
	case config.TPROXY:
		if conf.EgressRedirectIPv4Addr != "" || conf.EgressRedirectIPv6Addr != "" {
			return plugin.setupRedirectionIP(proto, conf)
		} else if conf.EgressPort != 0 {
			return plugin.redirectCIDRTrafficByTProxy(proto, iptable,
				plugin.getCidr(proto, conf), strconv.Itoa(conf.EgressPort))
		}
	}
	return nil
}

// setupRedirectionIP sets up the netfilter rules to redirect Egress VIP CIDR traffic
// to the given Egress RedirectionIP.
// Equivalent to ip route add ${vipCidr} via ${egressRedirectIp}
func (Plugin *Plugin) setupRedirectionIP(proto iptables.Protocol,
	netConf *config.NetConfig) error {
	if netConf.EgressRedirectIPv4Addr == "" && netConf.EgressRedirectIPv6Addr == "" {
		return nil
	}

	var dst *net.IPNet
	var redirectionIP net.IP
	if proto == iptables.ProtocolIPv6 {
		_, dst, _ = net.ParseCIDR(netConf.EgressIPv6CIDR)
		redirectionIP = net.ParseIP(netConf.EgressRedirectIPv6Addr)
	} else {
		_, dst, _ = net.ParseCIDR(netConf.EgressIPv4CIDR)
		redirectionIP = net.ParseIP(netConf.EgressRedirectIPv4Addr)
	}

	route := &netlink.Route{
		Dst: dst,
		Gw:  redirectionIP,
	}
	if err := netlink.RouteAdd(route); err != nil {
		log.Errorf("Adding IP route %v failed: %v", route, err)
		return err
	}
	return nil
}

// redirectCIDRTrafficByTProxy sets up all netfilter rules needed for Tproxy redirection
// of address in the VIPCIDR to the egress port.
func (plugin *Plugin) redirectCIDRTrafficByTProxy(
	proto iptables.Protocol,
	iptable *iptables.IPTables,
	vipCidr string,
	redirectPort string) error {

	// Reference: https://www.kernel.org/doc/Documentation/networking/tproxy.txt

	// Create a new chain.
	if err := iptable.NewChain("mangle", egressTProxyChain); err != nil {
		log.Errorf("Creating new IP table chain[%v] failed: %v", egressTProxyChain, err)
		return err
	}

	// Add TProxy marker.
	if err := iptable.Append("mangle", egressTProxyChain, "-j", "MARK",
		"--set-mark", strconv.Itoa(tproxyRouteMarker)); err != nil {
		log.Errorf("Adding TProxy Marker to the chain[%v] failed: %v", egressTProxyChain, err)
		return err
	}
	// Let the packet flow through.
	if err := iptable.Append("mangle", egressTProxyChain, "-j", "ACCEPT"); err != nil {
		log.Errorf("Accepting packets to the chain[%v] failed: %v", egressTProxyChain, err)
		return err
	}

	// Route packets through the TProxy chain.
	if err := iptable.Append("mangle", "PREROUTING", "-p", "tcp", "-m",
		"socket", "-j", egressTProxyChain); err != nil {
		log.Errorf("Routing packets through the chain[%v] failed: %v", egressTProxyChain, err)
		return err
	}

	// Add rule to packets marked with tproxyRouteMarker to be referenced with tproxyRouteTable.
	if err := plugin.addTproxyRouterRule(proto); err != nil {
		return err
	}

	// Add default rule to route all traffic to the loopback interface.
	if err := plugin.addDefaultTproxyRoute(proto); err != nil {
		return err
	}

	// For Egress Traffic, redirect anything going to SC VIP-CIDR to SC egress port.
	if err := iptable.Append("mangle", "PREROUTING", "-p", "tcp",
		"-m", "tcp", "-d", vipCidr, "-j", "TPROXY", "--tproxy-mark", tproxyMark, "--on-port",
		redirectPort); err != nil {
		log.Errorf("Redirecting traffic to the egress port failed : %v", err)
		return err
	}
	return nil
}

// getRuleFamily returns family corresponding to the protocol.
func (plugin *Plugin) getRuleFamily(proto iptables.Protocol) int {
	if proto == iptables.ProtocolIPv6 {
		return unix.AF_INET6
	} else {
		return unix.AF_INET
	}
}

// addTproxyRouterRule adds a new rule with packets marked with tproxyRouteMarker
// to be referenced to tproxyRouteTable.
// Equivalent to ip rule add fwmark <tproxyRouteMarker> lookup <tproxyRouteTable>
func (plugin *Plugin) addTproxyRouterRule(proto iptables.Protocol) error {
	handle, err := netlink.NewHandle()
	if err != nil {
		log.Errorf("Creating a new handle failed: %v", err)
		return err
	}

	rule := netlink.NewRule()
	rule.Family = plugin.getRuleFamily(proto)
	rule.Mark = tproxyRouteMarker
	rule.Table = tproxyRouteTable

	if err := handle.RuleAdd(rule); err != nil {
		log.Errorf("Add IP rule %v failed : %v", rule, err)
		return err
	}
	return nil
}

// addDefaultTproxyRoute creates a single default rule to route all traffic
// to the loopback interface.
// Equivalent to ip route add local 0.0.0.0/0 dev lo table <tproxyRouteTable>
func (plugin *Plugin) addDefaultTproxyRoute(proto iptables.Protocol) error {
	// Get loopback interface.
	link, err := netlink.LinkByName("lo")
	if err != nil {
		log.Errorf("Unable to get loopback interface : %v", err)
		return err
	}
	_, dst, _ := net.ParseCIDR(plugin.getDefaultCIDR(proto))

	route := &netlink.Route{
		Dst:       dst,
		Scope:     unix.RT_SCOPE_HOST,
		Type:      unix.RTN_LOCAL,
		Table:     tproxyRouteTable,
		LinkIndex: link.Attrs().Index,
	}
	if err = netlink.RouteAdd(route); err != nil {
		log.Errorf("Adding default IP route %v failed: %v", route, err)
		return err
	}
	log.Infof("Added route: %v", route)
	return nil
}

// getDefaultCIDR returns the CIDR representing default traffic based on the given protocol.
func (plugin *Plugin) getDefaultCIDR(proto iptables.Protocol) string {
	var cidr string
	if proto == iptables.ProtocolIPv6 {
		cidr = "::/0"
	} else {
		cidr = "0.0.0.0/0"
	}
	return cidr
}

// redirectCIDRTraffic sets rules to redirect traffic in the CIDR block to the egress port.
func (plugin *Plugin) redirectCIDRTrafficByNAT(
	iptable *iptables.IPTables,
	cidr string,
	redirectPort string) error {
	if err := iptable.Append("nat", "OUTPUT", "-p", "tcp", "-d", cidr,
		"-j", "REDIRECT", "--to-port", redirectPort); err != nil {
		log.Errorf("Append rule to redirect traffic of CIDR failed: %v", err)
		return err
	}
	return nil
}

// deleteEgressRules deletes the iptable rules for egress traffic.
func (plugin *Plugin) deleteEgressRules(
	iptable *iptables.IPTables,
	proto iptables.Protocol,
	netConf *config.NetConfig) error {
	switch netConf.EgressRedirectMode {
	case config.NAT:
		// Skip deleting rules when there is no egress listener port.
		if netConf.EgressPort != 0 {
			// Delete the CIDR redirection rules.
			return plugin.deleteCIDRRuleByNat(iptable, plugin.getCidr(proto, netConf),
				strconv.Itoa(netConf.EgressPort))
		}
	case config.TPROXY:
		handle, err := netlink.NewHandle()
		if err != nil {
			log.Errorf("Creating a new handle failed: %v", err)
			return err
		}
		if netConf.EgressRedirectIPv4Addr != "" || netConf.EgressRedirectIPv6Addr != "" {
			return plugin.deleteRedirectionIP(proto, netConf, handle)
		} else if netConf.EgressPort != 0 {
			return plugin.deleteCIDRRuleByTProxy(proto, iptable, plugin.getCidr(proto, netConf),
				strconv.Itoa(netConf.EgressPort), handle)
		}
	}
	return nil
}

// deleteCIDRRuleByTProxy removes all the rules setup for Tproxy based redirection.
func (plugin *Plugin) deleteCIDRRuleByTProxy(proto iptables.Protocol,
	iptable *iptables.IPTables,
	vipCidr string,
	redirectPort string,
	handle *netlink.Handle) error {
	// Removes all the rules that are setup for tproxy.
	// Reference: https://www.kernel.org/doc/Documentation/networking/tproxy.txt

	if err := iptable.Delete("mangle", "PREROUTING", "-p", "tcp", "-m",
		"socket", "-j", egressTProxyChain); err != nil {
		log.Errorf("Failed to remove chain: %v from mangle table", egressTProxyChain)
		return err
	}
	if err := plugin.removeChain(iptable, "mangle", egressTProxyChain); err != nil {
		return err
	}

	if err := plugin.deleteTproxyRouterRule(proto, handle); err != nil {
		return err
	}

	if err := plugin.deleteDefaultTproxyRoute(proto, handle); err != nil {
		return err
	}

	if err := iptable.Delete("mangle", "PREROUTING", "-p", "tcp",
		"-m", "tcp", "-d", vipCidr, "-j", "TPROXY", "--tproxy-mark", tproxyMark, "--on-port",
		redirectPort); err != nil {
		log.Errorf("Failed to remove traffic redirection rule to the egress port : %v", err)
		return err
	}
	return nil
}

// deleteRedirectionIP deletes the rules setup for redirecting traffic based on IP.
// Equivalent to ip route del ${vipCidr} via ${egressRedirectIp} dev <Interface>
func (plugin *Plugin) deleteRedirectionIP(proto iptables.Protocol, conf *config.NetConfig,
	handle *netlink.Handle) error {
	if conf.EgressRedirectIPv4Addr == "" && conf.EgressRedirectIPv6Addr == "" {
		return nil
	}

	var dst *net.IPNet
	var redirectionIP net.IP
	if proto == iptables.ProtocolIPv6 {
		_, dst, _ = net.ParseCIDR(conf.EgressIPv6CIDR)
		redirectionIP = net.ParseIP(conf.EgressRedirectIPv6Addr)
	} else {
		_, dst, _ = net.ParseCIDR(conf.EgressIPv4CIDR)
		redirectionIP = net.ParseIP(conf.EgressRedirectIPv4Addr)
	}

	route := &netlink.Route{
		Dst: dst,
		Gw:  redirectionIP,
	}
	routes, err := handle.RouteListFiltered(plugin.getRuleFamily(proto), route,
		netlink.RT_FILTER_DST|netlink.RT_FILTER_GW)
	for _, r := range routes {
		routeToBeDeleted := r
		if err = netlink.RouteDel(&routeToBeDeleted); err != nil {
			log.Errorf("Deleting default IP route %v failed: %v", routeToBeDeleted, err)
			return err
		}
	}
	return nil
}

// deleteTproxyRouterRule deletes the router rule setup for Tproxy redirection.
// Equivalent to ip rule del fwmark <tproxyRouteMarker> lookup <tproxyRouteTable>
func (plugin *Plugin) deleteTproxyRouterRule(proto iptables.Protocol,
	handle *netlink.Handle) error {
	existingRules, _ := handle.RuleList(plugin.getRuleFamily(proto))
	for _, r := range existingRules {
		if r.Table == tproxyRouteTable &&
			r.Mark == tproxyRouteMarker {
			ruleToBeDeleted := r
			if err := handle.RuleDel(&ruleToBeDeleted); err != nil {
				log.Errorf("Delete IP rule %v failed : %v", ruleToBeDeleted, err)
			}
			break
		}
	}
	return nil
}

// deleteDefaultTproxyRoute deletes the default ip route setup for Tproxy redirection.
// Equivalent to ip route del local 0.0.0.0/0 dev lo table <tproxyRouteTable>
func (plugin *Plugin) deleteDefaultTproxyRoute(proto iptables.Protocol,
	handle *netlink.Handle) error {
	// Get loopback interface.
	link, err := netlink.LinkByName("lo")
	if err != nil {
		log.Errorf("Unable to get loopback interface : %v", err)
		return err
	}
	route := &netlink.Route{
		Table:     tproxyRouteTable,
		LinkIndex: link.Attrs().Index,
	}
	routes, err := handle.RouteListFiltered(plugin.getRuleFamily(proto), route,
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
	for _, r := range routes {
		routeToBeDeleted := r
		if err = netlink.RouteDel(&routeToBeDeleted); err != nil {
			log.Errorf("Deleting default IP route %v failed: %v", routeToBeDeleted, err)
			// This is failing due to this bug: https://github.com/vishvananda/netlink/issues/670
		}
	}
	return nil
}

// getCidr returns the CIDR for the given protocol.
func (plugin *Plugin) getCidr(
	proto iptables.Protocol,
	config *config.NetConfig) string {
	var cidr string
	if proto == iptables.ProtocolIPv4 {
		cidr = config.EgressIPv4CIDR
	} else {
		cidr = config.EgressIPv6CIDR
	}
	return cidr
}

// deleteCIDRRuleByNat deletes the CIDR redirection rule set.
func (plugin *Plugin) deleteCIDRRuleByNat(
	iptable *iptables.IPTables,
	cidr string,
	redirectPort string) error {
	err := iptable.Delete("nat", "OUTPUT", "-p", "tcp", "-d", cidr,
		"-j", "REDIRECT", "--to-port", redirectPort)
	if err != nil {
		log.Errorf("Delete rule to redirect traffic of CIDR failed: %v", err)
	}
	return err
}
