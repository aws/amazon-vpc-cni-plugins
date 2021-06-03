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

package config

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
)

// NetConfig defines the network configuration for the vpc-eni plugin.
type NetConfig struct {
	cniTypes.NetConf
	ENIName            string
	ENIMACAddress      net.HardwareAddr
	ENIIPAddresses     []net.IPNet
	GatewayIPAddresses []net.IP
	UseExistingNetwork bool
}

// netConfigJSON defines the network configuration JSON file format for the vpc-eni plugin.
type netConfigJSON struct {
	cniTypes.NetConf
	ENIName            string   `json:"eniName"`
	ENIMACAddress      string   `json:"eniMACAddress"`
	ENIIPAddresses     []string `json:"eniIPAddresses"`
	GatewayIPAddresses []string `json:"gatewayIPAddresses"`
	UseExistingNetwork bool     `json:"useExistingNetwork"`
}

// New creates a new NetConfig object by parsing the given CNI arguments.
func New(args *cniSkel.CmdArgs) (*NetConfig, error) {
	// Parse network configuration.
	var config netConfigJSON
	err := json.Unmarshal(args.StdinData, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse network config: %v", err)
	}

	// Validate if all the required fields are present.

	// If we are supposed to use an existing network then network name is required.
	// This check is for backward compatibility in case older cni release versions are being used
	// which did not validate network name before addNetwork call.
	if config.UseExistingNetwork && config.Name == "" {
		return nil, fmt.Errorf("missing required parameter network name")
	}

	// If new network creation is required, then ENI Name or MAC and ENI IP addresses are required.
	if !config.UseExistingNetwork {
		if config.ENIName == "" && config.ENIMACAddress == "" {
			return nil, fmt.Errorf("missing required parameter ENIName or ENIMACAddress")
		}
		if len(config.ENIIPAddresses) == 0 {
			return nil, fmt.Errorf("missing required parameter ENIIPAddresses")
		}
	}

	// Parse the received config into NetConfig.
	netConfig := NetConfig{
		NetConf:            config.NetConf,
		ENIName:            config.ENIName,
		UseExistingNetwork: config.UseExistingNetwork,
	}

	// Parse the ENI MAC address.
	if config.ENIMACAddress != "" {
		netConfig.ENIMACAddress, err = net.ParseMAC(config.ENIMACAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid ENIMACAddress %s", config.ENIMACAddress)
		}
	}

	// Parse the ENI IP addresses.
	for _, ipAddr := range config.ENIIPAddresses {
		parsedIPAddr, err := vpc.GetIPAddressFromString(ipAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid ENIIPAddress %s", ipAddr)
		}
		netConfig.ENIIPAddresses = append(netConfig.ENIIPAddresses, *parsedIPAddr)
	}

	// Parse the optional gateway IP addresses.
	for _, gatewayIPAddr := range config.GatewayIPAddresses {
		parsedGatewayIPAddr := net.ParseIP(gatewayIPAddr)
		if parsedGatewayIPAddr == nil {
			return nil, fmt.Errorf("invalid GatewayIPAddress %s", gatewayIPAddr)
		}
		netConfig.GatewayIPAddresses = append(netConfig.GatewayIPAddresses, parsedGatewayIPAddr)
	}

	// Validation complete. Return the parsed NetConfig object.
	log.Debugf("Created NetConfig: %+v.", netConfig)
	return &netConfig, nil
}
