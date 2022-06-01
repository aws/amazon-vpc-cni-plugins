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
	"strconv"

	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/ecs-serviceconnect/config"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesCurrent "github.com/containernetworking/cni/pkg/types/current"
	"github.com/coreos/go-iptables/iptables"
)

const (
	// Names of iptables chains created for ECS Service Connect rules.
	ingressChain = "ECS_SERVICE_CONNECT_INGRESS"
	egressChain  = "ECS_SERVICE_CONNECT_EGRESS"
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
	log.Debugf("Searching for netns %s.", args.Netns)
	ns, err := netns.GetNetNS(args.Netns)
	if err != nil {
		log.Errorf("Failed to find netns %s: %v.", args.Netns, err)
		return err
	}

	// Add IP rules in the target network namespace.
	err = ns.Run(func() error {
		for _, proto := range netConfig.IPProtocols {
			if err = plugin.setupIptablesRules(proto, netConfig); err != nil {
				log.Errorf("Failed to set up iptables rules: %v.", err)
				return err
			}
		}
		return nil
	})
	result := &cniTypesCurrent.Result{
		Interfaces: []*cniTypesCurrent.Interface{
			{
				Name:    args.IfName,
				Sandbox: args.Netns,
			},
		},
	}
	return cniTypes.PrintResult(result, netConfig.CNIVersion)
}

// Del is the internal implementation of CNI DEL command.
// CNI DEL command can be called by the orchestrator multiple times for the same interface,
// and thus must be best-effort and idempotent.
func (plugin *Plugin) Del(args *cniSkel.CmdArgs) error {
	// Parse network configuration.
	netConfig, err := config.New(args)
	if err != nil {
		log.Errorf("Failed to parse netconfig from args: %v.", err)
		return err
	}

	log.Infof("Executing DEL with netconfig: %+v.", netConfig)

	// Search for the target network namespace.
	ns, err := netns.GetNetNS(args.Netns)
	if err != nil {
		log.Errorf("Failed to find netns %s: %v.", args.Netns, err)
		return err
	}

	// Delete IP rules in the target network namespace.
	err = ns.Run(func() error {
		for _, proto := range netConfig.IPProtocols {
			if err = plugin.deleteIptablesRules(proto, netConfig); err != nil {
				log.Errorf("Failed to delete ip rules: %v.", err)
				return err
			}
		}
		return nil
	})
	return err
}

// setupIptablesRules sets iptables/ip6tables rules in container network namespace.
func (plugin *Plugin) setupIptablesRules(proto iptables.Protocol, config *config.NetConfig) error {
	// Create a new iptables object.
	iptable, err := iptables.NewWithProtocol(proto)
	if err != nil {
		return err
	}
	// Setup Ingress rules
	if err = plugin.setupIngressRules(iptable, config); err != nil {
		return err
	}
	// Setup Egress rules
	return plugin.setupEgressRules(iptable, proto, config)
}

// setupIngressRules sets Ingress port redirection rules in the network namespace.
func (plugin *Plugin) setupIngressRules(
	iptable *iptables.IPTables,
	config *config.NetConfig) error {
	// Skip setting rules when there is no redirection.
	if len(config.IngressListenerToInterceptPortMap) == 0 {
		return nil
	}

	//TODO: Handle bridge mode.

	// Redirect non-local traffic to the redirection port.
	return plugin.redirectNonLocalTraffic(iptable, ingressChain, config.IngressListenerToInterceptPortMap)
}

// setupEgressRules sets Egress port redirection rules in the network namespace.
func (plugin *Plugin) setupEgressRules(
	iptable *iptables.IPTables,
	proto iptables.Protocol,
	config *config.NetConfig) error {
	// Skip setting rules when there is no egress listener port.
	if config.EgressPort == 0 {
		return nil
	}

	//TODO: Handle Bridge mode.

	// Redirect traffic in the CIDR block to the egress port.
	return plugin.redirectCIDRTraffic(iptable, plugin.getCidr(proto, config), strconv.Itoa(config.EgressPort))
}

// redirectCIDRTraffic sets rules to redirect traffic in the CIDR block to the egress port.
func (plugin *Plugin) redirectCIDRTraffic(
	iptable *iptables.IPTables,
	cidr string,
	redirectPort string) error {
	err := iptable.Append("nat", "OUTPUT", "-p", "tcp", "-d", cidr,
		"-j", "REDIRECT", "--to-port", redirectPort)

	if err != nil {
		log.Errorf("Append rule to redirect traffic of CIDR failed: %v", err)
	}

	return err
}

// deleteIptablesRules removes iptables/ip6tables rules in container network namespace.
func (plugin *Plugin) deleteIptablesRules(
	proto iptables.Protocol,
	config *config.NetConfig) error {
	/// Create a new iptables session.
	iptable, err := iptables.NewWithProtocol(proto)
	if err != nil {
		return err
	}

	// Delete Ingress rules
	if err = plugin.deleteIngressRules(iptable, config); err != nil {
		return err
	}

	// Delete Egress rules
	return plugin.deleteEgressRules(iptable, proto, config)
}

// deleteIngressRules deletes the iptable rules for ingress traffic.
func (plugin *Plugin) deleteIngressRules(
	iptable *iptables.IPTables,
	config *config.NetConfig) error {
	// Skip deleting rules when there is no redirection.
	if len(config.IngressListenerToInterceptPortMap) == 0 {
		return nil
	}
	// Delete ingress rule from iptables.
	if err := plugin.deleteNonLocalRedirectionRules(iptable, ingressChain); err != nil {
		log.Errorf("Delete the rule in PREROUTING chain failed: %v", err)
		return err
	}
	// Remove the added chain.
	return plugin.removeChain(iptable, ingressChain)
}

// deleteEgressRules deletes the iptable rules for egress traffic.
func (plugin *Plugin) deleteEgressRules(
	iptable *iptables.IPTables,
	proto iptables.Protocol,
	config *config.NetConfig) error {
	// Skip deleting rules when there is no egress listener port
	if config.EgressPort == 0 {
		return nil
	}
	// Delete the CIDR redirection rules.
	return plugin.deleteCIDRRedirectionRule(iptable, plugin.getCidr(proto, config), strconv.Itoa(config.EgressPort))
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

// deleteCIDRRedirectionRule deletes the CIDR redirection rule set.
func (plugin *Plugin) deleteCIDRRedirectionRule(
	iptable *iptables.IPTables,
	cidr string,
	redirectPort string) error {
	err := iptable.Delete("nat", "OUTPUT", "-p", "tcp", "-d", cidr,
		"-j", "REDIRECT", "--to-port", redirectPort)
	// TODO: Remove other rules.
	if err != nil {
		log.Errorf("Delete rule to redirect traffic of CIDR failed: %v", err)
	}
	return err
}

// redirectNonLocalTraffic adds iptable rules to the given chain to route non-local traffic
// coming in from the given listener port to intercept ports and adds the chain
// to the NAT table at PREROUTING stage.
func (plugin *Plugin) redirectNonLocalTraffic(
	iptable *iptables.IPTables,
	chain string,
	listenerPortToInterceptPort map[int]int) error {

	// Create a new chain.
	err := iptable.NewChain("nat", chain)
	if err != nil {
		log.Errorf("Create new IP table chain[%v] failed: %v", chain, err)
		return err
	}

	// Route everything arriving at intercept ports to listener port.
	for listenerPort, interceptPort := range listenerPortToInterceptPort {
		err := iptable.Append("nat", chain, "-p", "tcp", "--dport", strconv.Itoa(interceptPort),
			"-j", "REDIRECT", "--to-port", strconv.Itoa(listenerPort))
		if err != nil {
			log.Errorf("Append rule to redirect traffic to Port in chain[%v] failed: %v", chain, err)
			return err
		}
	}

	// Apply the chain to everything non-local.
	err = iptable.Append("nat", "PREROUTING", "-p", "tcp", "-m", "addrtype", "!", "--src-type",
		"LOCAL", "-j", chain)
	if err != nil {
		log.Errorf("Append rule to jump from PREROUTING to chain[%v] failed: %v", chain, err)
		return err
	}
	return nil
}

// deleteNonLocalRedirectionRules deletes the non-local traffic to the given chain in NAT table at PREROUTING stage.
func (plugin *Plugin) deleteNonLocalRedirectionRules(
	iptable *iptables.IPTables,
	chain string) error {
	err := iptable.Delete("nat", "PREROUTING", "-p", "tcp", "-m", "addrtype", "!", "--src-type",
		"LOCAL", "-j", chain)
	if err != nil {
		log.Errorf("Delete rule to redirect Non local traffic to chain[%v] failed: %v", chain, err)
		return err
	}
	return nil
}

// removeChain flushes and deletes the given chain.
func (plugin *Plugin) removeChain(
	iptable *iptables.IPTables,
	chain string) error {
	// Flush and delete the chain.
	err := iptable.ClearChain("nat", chain)
	if err != nil {
		log.Errorf("Failed to flush rules in chain[%v]: %v", chain, err)
		return err
	}
	err = iptable.DeleteChain("nat", chain)
	if err != nil {
		log.Errorf("Failed to delete chain[%v]: %v", chain, err)
		return err
	}
	return nil
}
