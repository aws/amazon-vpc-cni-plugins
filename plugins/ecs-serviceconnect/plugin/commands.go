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
	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/ecs-serviceconnect/config"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesCurrent "github.com/containernetworking/cni/pkg/types/100"
	"github.com/coreos/go-iptables/iptables"
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
			if err = plugin.setupNetfilterRules(proto, netConfig); err != nil {
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
			if err = plugin.deleteNetfilterRules(proto, netConfig); err != nil {
				log.Errorf("Failed to delete netfilter rules: %v.", err)
				return err
			}
		}
		return nil
	})
	return err
}

// setupNetfilterRules sets up rules in container network namespace.
func (plugin *Plugin) setupNetfilterRules(proto iptables.Protocol,
	config *config.NetConfig) error {
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

// deleteNetfilterRules removes all the netfilter rules added in container network namespace.
func (plugin *Plugin) deleteNetfilterRules(
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

// removeChain flushes and deletes the given chain.
func (plugin *Plugin) removeChain(iptable *iptables.IPTables, table string, chain string) error {
	// Flush and delete the chain.
	err := iptable.ClearChain(table, chain)
	if err != nil {
		log.Errorf("Failed to flush rules in chain[%v]: %v", chain, err)
		return err
	}
	err = iptable.DeleteChain(table, chain)
	if err != nil {
		log.Errorf("Failed to delete chain[%v]: %v", chain, err)
		return err
	}
	return nil
}
