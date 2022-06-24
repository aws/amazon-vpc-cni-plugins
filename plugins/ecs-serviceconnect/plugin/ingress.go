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

	"github.com/aws/amazon-vpc-cni-plugins/plugins/ecs-serviceconnect/config"

	log "github.com/cihub/seelog"
	"github.com/coreos/go-iptables/iptables"
)

const (
	// Ingress iptables chain created for ECS Service Connect rules.
	ingressChain = "ECS_SERVICE_CONNECT_INGRESS"
)

// setupIngressRules sets Ingress port redirection rules in the network namespace.
func (plugin *Plugin) setupIngressRules(
	iptable *iptables.IPTables,
	config *config.NetConfig) error {
	// Skip setting rules when there is no redirection.
	if len(config.IngressListenerToInterceptPortMap) == 0 {
		return nil
	}

	// Redirect non-local traffic to the redirection port.
	return plugin.redirectNonLocalTraffic(iptable, ingressChain,
		config.IngressListenerToInterceptPortMap)
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
	return plugin.removeChain(iptable, "nat", ingressChain)
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
		err := iptable.Append("nat", chain, "-p", "tcp", "--dport",
			strconv.Itoa(interceptPort), "-j", "REDIRECT", "--to-port", strconv.Itoa(listenerPort))
		if err != nil {
			log.Errorf("Append rule to redirect traffic to Port in chain[%v] failed: %v",
				chain, err)
			return err
		}
	}

	// Apply the chain to everything non-local.
	err = iptable.Append("nat", "PREROUTING", "-p", "tcp", "-m", "addrtype",
		"!", "--src-type", "LOCAL", "-j", chain)
	if err != nil {
		log.Errorf("Append rule to jump from PREROUTING to chain[%v] failed: %v", chain, err)
		return err
	}
	return nil
}

// deleteNonLocalRedirectionRules deletes the non-local traffic to the given chain in NAT table
// at PREROUTING stage.
func (plugin *Plugin) deleteNonLocalRedirectionRules(
	iptable *iptables.IPTables,
	chain string) error {
	err := iptable.Delete("nat", "PREROUTING", "-p", "tcp", "-m", "addrtype",
		"!", "--src-type", "LOCAL", "-j", chain)
	if err != nil {
		log.Errorf("Delete rule to redirect Non local traffic to chain[%v] failed: %v",
			chain, err)
		return err
	}
	return nil
}
