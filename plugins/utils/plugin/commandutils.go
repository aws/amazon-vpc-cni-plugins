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
	log "github.com/cihub/seelog"
	"github.com/coreos/go-iptables/iptables"
)

// RedirectNonLocalTraffic adds iptable rules to the given chain to route non-local traffic coming in from the
// given listener port to intercept ports and adds the chain to the NAT table at PREROUTING stage
func RedirectNonLocalTraffic(
	iptable *iptables.IPTables,
	chain string,
	listenerPortToInterceptPorts map[string]string) error {

	// Create a new chain
	err := iptable.NewChain("nat", chain)
	if err != nil {
		log.Errorf("Create new IP table chain[%v] failed: %v", chain, err)
		return err
	}

	// Route everything arriving at intercept ports to listener port.
	for listenerPort, interceptPorts := range listenerPortToInterceptPorts {
		err := iptable.Append("nat", chain, "-p", "tcp", "-m", "multiport", "--dports", interceptPorts,
			"-j", "REDIRECT", "--to-port", listenerPort)
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

// DeleteNonLocalRedirectionRules deletes the non-local traffic to the given chain in NAT table at PREROUTING stage
func DeleteNonLocalRedirectionRules(
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

// RemoveChain flushes and deletes the given chain
func RemoveChain(
	iptable *iptables.IPTables,
	chain string) error {
	// flush and delete the chain.
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
