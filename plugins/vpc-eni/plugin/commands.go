// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package plugin

import (
	"github.com/aws/amazon-vpc-cni-plugins/network/eni"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-eni/config"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-eni/network"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesCurrent "github.com/containernetworking/cni/pkg/types/100"
)

// Add is the CNI ADD command handler.
func (plugin *Plugin) Add(args *cniSkel.CmdArgs) error {
	// Parse network configuration.
	netConfig, err := config.New(args)
	if err != nil {
		log.Errorf("Failed to parse netconfig from args: %v.", err)
		return err
	}

	log.Infof("Executing ADD with netconfig: %+v ContainerID:%v Netns:%v IfName:%v Args:%v.",
		netConfig, args.ContainerID, args.Netns, args.IfName, args.Args)

	var vpcENI *eni.ENI
	// If existing network is to be used then ENI is not required.
	if !netConfig.UseExistingNetwork {
		// Find the ENI.
		vpcENI, err = eni.NewENI(netConfig.ENIName, netConfig.ENIMACAddress)
		if err != nil {
			log.Errorf("Failed to find ENI %s: %v.", netConfig.ENIName, err)
			return err
		}
	}

	// Call the operating system specific network builder.
	nb := plugin.nb

	// Find or create the container network with the given ENI.
	nw := network.Network{
		Name:                netConfig.Name,
		ENI:                 vpcENI,
		IPAddresses:         netConfig.ENIIPAddresses,
		GatewayIPAddresses:  netConfig.GatewayIPAddresses,
		DNSServers:          netConfig.DNS.Nameservers,
		DNSSuffixSearchList: netConfig.DNS.Search,
		UseExisting:         netConfig.UseExistingNetwork,
	}

	err = nb.FindOrCreateNetwork(&nw)
	if err != nil {
		log.Errorf("Failed to create network: %v.", err)
		return err
	}

	// Find or create the container endpoint on the network.
	ep := network.Endpoint{
		ContainerID: args.ContainerID,
		NetNSName:   args.Netns,
		MACAddress:  netConfig.ENIMACAddress,
		IPAddresses: netConfig.ENIIPAddresses,
		BlockIMDS:   netConfig.BlockIMDS,
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
		IPs: []*cniTypesCurrent.IPConfig{
			{
				Interface: cniTypesCurrent.Int(0),
				Address:   ep.IPAddresses[0],
				Gateway:   nw.GatewayIPAddresses[0],
			},
		},
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
	netConfig, err := config.New(args)
	if err != nil {
		log.Errorf("Failed to parse netconfig from args: %v.", err)
		return err
	}

	log.Infof("Executing DEL with netconfig: %+v ContainerID:%v Netns:%v IfName:%v Args:%v.",
		netConfig, args.ContainerID, args.Netns, args.IfName, args.Args)

	var vpcENI *eni.ENI
	// If existing network is to be used then ENI is not required.
	if !netConfig.UseExistingNetwork {
		// Find the ENI.
		vpcENI, err = eni.NewENI(netConfig.ENIName, netConfig.ENIMACAddress)
		if err != nil {
			log.Errorf("Failed to find ENI %s: %v.", netConfig.ENIName, err)
			return err
		}
	}

	// Call operating system specific handler.
	nb := plugin.nb

	nw := network.Network{
		Name:        netConfig.Name,
		ENI:         vpcENI,
		UseExisting: netConfig.UseExistingNetwork,
	}

	ep := network.Endpoint{
		ContainerID: args.ContainerID,
		NetNSName:   args.Netns,
		IPAddresses: netConfig.ENIIPAddresses,
		MACAddress:  netConfig.ENIMACAddress,
	}

	err = nb.DeleteEndpoint(&nw, &ep)
	if err != nil {
		// DEL is best-effort. Log and ignore the failure.
		log.Errorf("Failed to delete endpoint, ignoring: %v.", err)
	}

	// Do not delete pre-existing networks.
	if !nw.UseExisting {
		err = nb.DeleteNetwork(&nw)
		if err != nil {
			log.Errorf("Failed to delete network: %v.", err)
			return err
		}
	}

	return nil
}
