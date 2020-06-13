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

package plugin

import (
	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/aws-appmesh/config"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/coreos/go-iptables/iptables"
)

const (
	// Names of iptables chains created for App Mesh rules.
	ingressChain = "APPMESH_INGRESS"
	egressChain  = "APPMESH_EGRESS"
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
		var err error
		ipProtoMap := make(map[iptables.Protocol]string)
		ipProtoMap[iptables.ProtocolIPv4] = netConfig.EgressIgnoredIPv4s
		if netConfig.EnableIPv6 {
			ipProtoMap[iptables.ProtocolIPv6] = netConfig.EgressIgnoredIPv6s
		}

		for proto, ignoredIPs := range ipProtoMap {
			err = plugin.setupIptablesRules(proto, netConfig, ignoredIPs)
			if err != nil {
				log.Errorf("Failed to set up iptables rules: %v.", err)
				return err
			}
		}

		return nil
	})

	if err != nil {
		return err
	}

	// Pass through the previous result.
	log.Infof("Writing CNI result to stdout: %+v", netConfig.PrevResult)

	return cniTypes.PrintResult(netConfig.PrevResult, netConfig.CNIVersion)
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
		ipProtos := []iptables.Protocol{iptables.ProtocolIPv4}
		if netConfig.EnableIPv6 {
			ipProtos = append(ipProtos, iptables.ProtocolIPv6)
		}

		for _, proto := range ipProtos {
			err = plugin.deleteIptablesRules(proto, netConfig)
			if err != nil {
				log.Errorf("Failed to delete ip rules: %v.", err)
				return err
			}
		}

		return nil
	})

	return err
}

// setupIptablesRules sets iptables/ip6tables rules in container network namespace.
func (plugin *Plugin) setupIptablesRules(
	proto iptables.Protocol,
	config *config.NetConfig,
	egressIgnoredIPs string) error {
	// Create a new iptables object.
	iptable, err := iptables.NewWithProtocol(proto)
	if err != nil {
		return err
	}

	err = plugin.setupIngressRules(iptable, config)
	if err != nil {
		return err
	}

	err = plugin.setupEgressRules(iptable, config, egressIgnoredIPs)
	if err != nil {
		return err
	}

	return nil
}

// setupEgressRules installs iptable rules to handle egress traffic.
func (plugin *Plugin) setupEgressRules(
	iptable *iptables.IPTables,
	config *config.NetConfig,
	egressIgnoredIPs string) error {

	// Create new chains.
	err := iptable.NewChain("nat", egressChain)
	if err != nil {
		return err
	}

	// Set up for outgoing traffic.
	if config.IgnoredUID != "" {
		err = iptable.Append("nat", egressChain, "-m", "owner", "--uid-owner", config.IgnoredUID, "-j", "RETURN")
		if err != nil {
			log.Errorf("Append rule for ignoredUID failed: %v", err)
			return err
		}
	}

	if config.IgnoredGID != "" {
		err = iptable.Append("nat", egressChain, "-m", "owner", "--gid-owner", config.IgnoredGID, "-j", "RETURN")
		if err != nil {
			log.Errorf("Append rule for ignoredGID failed: %v", err)
			return err
		}
	}

	if config.EgressIgnoredPorts != "" {
		err = iptable.Append("nat", egressChain, "-p", "tcp", "-m", "multiport", "--dports",
			config.EgressIgnoredPorts, "-j", "RETURN")
		if err != nil {
			log.Errorf("Append rule for egressIgnoredPorts failed: %v", err)
			return err
		}
	}

	if egressIgnoredIPs != "" {
		err = iptable.Append("nat", egressChain, "-p", "tcp", "-d", egressIgnoredIPs, "-j", "RETURN")
		if err != nil {
			log.Errorf("Append rule for egressIgnoredIPs failed: %v", err)
			return err
		}
	}

	// Redirect everything that is not ignored.
	err = iptable.Append("nat", egressChain, "-p", "tcp", "-j", "REDIRECT", "--to", config.ProxyEgressPort)
	if err != nil {
		log.Errorf("Append rule to redirect traffic to proxyEgressPort failed: %v", err)
		return err
	}

	// Apply egress chain to non local traffic.
	err = iptable.Append("nat", "OUTPUT", "-p", "tcp", "-m", "addrtype", "!", "--dst-type",
		"LOCAL", "-j", egressChain)
	if err != nil {
		log.Errorf("Append rule to jump from OUTPUT to egress chain failed: %v", err)
		return err
	}

	return nil
}

// setupIngressRules installs iptable rules to handle ingress traffic.
func (plugin *Plugin) setupIngressRules(
	iptable *iptables.IPTables,
	config *config.NetConfig) error {
	if config.ProxyIngressPort == "" || len(config.AppPorts) == 0 {
		return nil
	}

	err := iptable.NewChain("nat", ingressChain)
	if err != nil {
		return err
	}

	// Route everything arriving at the application port to proxy.
	err = iptable.Append("nat", ingressChain, "-p", "tcp", "-m", "multiport", "--dports", config.AppPorts,
		"-j", "REDIRECT", "--to-port", config.ProxyIngressPort)
	if err != nil {
		log.Errorf("Append rule to redirect traffic to proxyIngressPort failed: %v", err)
		return err
	}

	// Apply ingress chain to everything non-local.
	err = iptable.Append("nat", "PREROUTING", "-p", "tcp", "-m", "addrtype", "!", "--src-type",
		"LOCAL", "-j", ingressChain)
	if err != nil {
		log.Errorf("Append rule to jump from PREROUTING to ingress chain failed: %v", err)
		return err
	}

	return nil
}

// deleteIptablesRules deletes iptables/ip6tables rules in container network namespace.
func (plugin *Plugin) deleteIptablesRules(
	proto iptables.Protocol,
	config *config.NetConfig) error {
	/// Create a new iptables session.
	iptable, err := iptables.NewWithProtocol(proto)
	if err != nil {
		return err
	}

	err = plugin.deleteIngressRules(iptable, config)
	if err != nil {
		return err
	}

	err = plugin.deleteEgressRules(iptable)
	if err != nil {
		return err
	}

	return nil
}

// deleteIngressRules deletes the iptable rules for ingress traffic.
func (plugin *Plugin) deleteIngressRules(
	iptable *iptables.IPTables,
	config *config.NetConfig) error {
	if config.ProxyIngressPort == "" {
		return nil
	}
	// Delete ingress rule from iptables.
	err := iptable.Delete("nat", "PREROUTING", "-p", "tcp", "-m", "addrtype", "!", "--src-type",
		"LOCAL", "-j", ingressChain)
	if err != nil {
		log.Errorf("Delete the rule in PREROUTING chain failed: %v", err)
		return err
	}

	// flush and delete ingress chain.
	err = iptable.ClearChain("nat", ingressChain)
	if err != nil {
		log.Errorf("Failed to flush rules in chain[%v]: %v", ingressChain, err)
		return err
	}
	err = iptable.DeleteChain("nat", ingressChain)
	if err != nil {
		log.Errorf("Failed to delete chain[%v]: %v", ingressChain, err)
		return err
	}

	return nil
}

// deleteEgressRules deletes the iptable rules for egress traffic.
func (plugin *Plugin) deleteEgressRules(iptable *iptables.IPTables) error {
	// Delete egress rule from iptables.
	err := iptable.Delete("nat", "OUTPUT", "-p", "tcp", "-m", "addrtype", "!", "--dst-type",
		"LOCAL", "-j", egressChain)
	if err != nil {
		log.Errorf("Delete the rule in OUTPUT chain failed: %v", err)
		return err
	}

	// flush and delete egress chain.
	err = iptable.ClearChain("nat", egressChain)
	if err != nil {
		log.Errorf("Failed to flush rules in chain[%v]: %v", egressChain, err)
		return err
	}
	err = iptable.DeleteChain("nat", egressChain)
	if err != nil {
		log.Errorf("Failed to delete chain[%v]: %v", egressChain, err)
		return err
	}

	return nil
}
