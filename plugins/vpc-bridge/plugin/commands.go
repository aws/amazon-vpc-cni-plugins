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

package plugin

import (
	"github.com/aws/amazon-vpc-cni-plugins/network/eni"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-bridge/config"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-bridge/network"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesCurrent "github.com/containernetworking/cni/pkg/types/current"
)

// Add is the CNI ADD command handler.
func (plugin *Plugin) Add(args *cniSkel.CmdArgs) error {
	// Parse network configuration.
	netConfig, err := config.New(args, true)
	if err != nil {
		log.Errorf("Failed to parse netconfig from args: %v.", err)
		return err
	}

	log.Infof("Executing ADD with netconfig: %+v ContainerID:%v Netns:%v IfName:%v Args:%v.",
		netConfig, args.ContainerID, args.Netns, args.IfName, args.Args)

	// Find the ENI.
	sharedENI, err := eni.NewENI(netConfig.ENIName, netConfig.ENIMACAddress)
	if err != nil {
		log.Errorf("Failed to find ENI %s: %v.", netConfig.ENIName, err)
		return err
	}

	// Find the ENI link.
	err = sharedENI.AttachToLink()
	if err != nil {
		log.Errorf("Failed to find ENI link: %v.", err)
		return err
	}

	// Call the operating system specific network builder.
	nb := plugin.nb

	// Find or create the container network for the shared ENI.
	nw := network.Network{
		Name:                netConfig.Name,
		BridgeType:          netConfig.BridgeType,
		BridgeNetNSPath:     netConfig.BridgeNetNSPath,
		SharedENI:           sharedENI,
		ENIIPAddresses:      netConfig.ENIIPAddresses,
		GatewayIPAddress:    netConfig.GatewayIPAddress,
		VPCCIDRs:            netConfig.VPCCIDRs,
		DNSServers:          netConfig.DNS.Nameservers,
		DNSSuffixSearchList: netConfig.DNS.Search,
	}

	if netConfig.Kubernetes != nil {
		nw.ServiceCIDR = netConfig.Kubernetes.ServiceCIDR
	}

	// Below creates a bridge but doesn't require attaching any IPs given it is L3 bridge not L2
	err = nb.FindOrCreateNetwork(&nw)
	if err != nil {
		log.Errorf("Failed to create network: %v.", err)
		return err
	}

	// Find or create the container endpoint on the network.
	ep := network.Endpoint{
		ContainerID:  args.ContainerID,
		NetNSName:    args.Netns,
		IfName:       args.IfName,
		IfType:       netConfig.InterfaceType,
		TapUserID:    netConfig.TapUserID,
		IPAddresses:  netConfig.IPAddresses,
		PortMappings: netConfig.PortMappings,
	}

	err = nb.FindOrCreateEndpoint(&nw, &ep)
	if err != nil {
		log.Errorf("Failed to create endpoint: %v.", err)
		return err
	}

	// Generate CNI result.
	result := &cniTypesCurrent.Result{
		Interfaces: []*cniTypesCurrent.Interface{
			{
				Name:    args.IfName,
				Mac:     ep.MACAddress.String(),
				Sandbox: args.Netns,
			},
		},
	}

	// Populate an IPConfig entry for each IP address.
	for _, ipAddr := range netConfig.IPAddresses {
		ipCfg := &cniTypesCurrent.IPConfig{
			Interface: cniTypesCurrent.Int(0),
			Address:   ipAddr,
		}

		if ipAddr.IP.To4() != nil {
			ipCfg.Version = "4"
			ipCfg.Gateway = netConfig.GatewayIPAddress
		} else {
			ipCfg.Version = "6"

			// Kubernetes doesn't implement dual-stack behavior properly. It defaults to IPv4 if
			// both an IPv4 and IPv6 address are present. Work around that by reporting only the
			// first IPv6 address in dual-stack setups.
			if netConfig.Kubernetes != nil {
				result.IPs = []*cniTypesCurrent.IPConfig{ipCfg}
				break
			}
		}

		result.IPs = append(result.IPs, ipCfg)
	}

	// Output CNI result.
	log.Infof("Writing CNI result to stdout: %+v", result)
	err = cniTypes.PrintResult(result, netConfig.CNIVersion)
	if err != nil {
		log.Errorf("Failed to print result for CNI ADD command: %v", err)
	}

	return err
}

// Del is the CNI DEL command handler.
func (plugin *Plugin) Del(args *cniSkel.CmdArgs) error {
	// Parse network configuration.
	netConfig, err := config.New(args, false)
	if err != nil {
		log.Errorf("Failed to parse netconfig from args: %v.", err)
		return err
	}

	log.Infof("Executing DEL with netconfig: %+v ContainerID:%v Netns:%v IfName:%v Args:%v.",
		netConfig, args.ContainerID, args.Netns, args.IfName, args.Args)

	// Find the ENI.
	sharedENI, err := eni.NewENI(netConfig.ENIName, netConfig.ENIMACAddress)
	if err != nil {
		log.Errorf("Failed to find ENI %s: %v.", netConfig.ENIName, err)
		return err
	}

	// Find the ENI link.
	err = sharedENI.AttachToLink()
	if err != nil {
		log.Errorf("Failed to find ENI link: %v.", err)
		return err
	}

	// Call operating system specific handler.
	nb := plugin.nb

	nw := network.Network{
		Name:            netConfig.Name,
		BridgeType:      netConfig.BridgeType,
		BridgeNetNSPath: netConfig.BridgeNetNSPath,
		SharedENI:       sharedENI,
	}

	ep := network.Endpoint{
		ContainerID: args.ContainerID,
		NetNSName:   args.Netns,
		IfName:      args.IfName,
		IfType:      netConfig.InterfaceType,
		TapUserID:   netConfig.TapUserID,
		IPAddresses: netConfig.IPAddresses,
	}

	err = nb.DeleteEndpoint(&nw, &ep)
	if err != nil {
		// DEL is best-effort. Log and ignore the failure.
		log.Errorf("Failed to delete endpoint, ignoring: %v", err)
	}

	return nil
}
