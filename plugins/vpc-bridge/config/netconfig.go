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

package config

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
)

// NetConfig defines the network configuration for the vpc-bridge plugin.
type NetConfig struct {
	cniTypes.NetConf
	ENIName          string
	ENIMACAddress    net.HardwareAddr
	ENIIPAddresses   []net.IPNet
	VPCCIDRs         []net.IPNet
	BridgeType       string
	BridgeNetNSPath  string
	IPAddresses      []net.IPNet
	GatewayIPAddress net.IP
	PortMappings     []vpc.PortMapping
	InterfaceType    string
	TapUserID        int
	Kubernetes       *KubernetesConfig
}

// netConfigJSON defines the network configuration JSON file format for the vpc-bridge plugin.
type netConfigJSON struct {
	cniTypes.NetConf
	// Options to be passed in by the runtime
	RuntimeConfig RuntimeConfig `json:"runtimeConfig"`
	// Other explicit options
	ENIName          string   `json:"eniName"`
	ENIMACAddress    string   `json:"eniMACAddress"`
	ENIIPAddresses   []string `json:"eniIPAddresses"`
	VPCCIDRs         []string `json:"vpcCIDRs"`
	BridgeType       string   `json:"bridgeType"`
	BridgeNetNSPath  string   `json:"bridgeNetNSPath"`
	IPAddresses      []string `json:"ipAddresses"`
	GatewayIPAddress string   `json:"gatewayIPAddress"`
	InterfaceType    string   `json:"interfaceType"`
	TapUserID        string   `json:"tapUserID"`
	ServiceCIDR      string   `json:"serviceCIDR"`
}

// RuntimeConfig are the runtime options which will be populated dynamically by the runtime
// based on the requested capability.
// https://www.cni.dev/docs/conventions/#dynamic-plugin-specific-fields-capabilities--runtime-configuration
type RuntimeConfig struct {
	PortMappings []vpc.PortMapping `json:"portMappings,omitempty"`
}

const (
	// Bridge network namespace defaults to the host network namespace (empty string),
	// or more precisely, whichever namespace the CNI plugin is running in.
	defaultBridgeNetNSPath = ""

	// Bridge type values.
	BridgeTypeL2 = "L2"
	BridgeTypeL3 = "L3"

	// Interface type values.
	IfTypeVETH = "veth"
	IfTypeTAP  = "tap"
)

// New creates a new NetConfig object by parsing the given CNI arguments.
func New(args *cniSkel.CmdArgs, isAddCmd bool) (*NetConfig, error) {
	// Parse network configuration.
	var config netConfigJSON
	err := json.Unmarshal(args.StdinData, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse network config: %v", err)
	}

	// Validate if all the required fields are present.
	if config.ENIName == "" && config.ENIMACAddress == "" {
		return nil, fmt.Errorf("missing required parameter ENIName or ENIMACAddress")
	}

	// Set defaults.
	if config.BridgeType == "" {
		config.BridgeType = BridgeTypeL3
	}

	if config.BridgeNetNSPath == "" {
		config.BridgeNetNSPath = defaultBridgeNetNSPath
	}

	if config.InterfaceType == "" {
		config.InterfaceType = IfTypeVETH
	}

	// Populate NetConfig.
	netConfig := NetConfig{
		NetConf:         config.NetConf,
		ENIName:         config.ENIName,
		BridgeType:      config.BridgeType,
		BridgeNetNSPath: config.BridgeNetNSPath,
		InterfaceType:   config.InterfaceType,
		PortMappings:    config.RuntimeConfig.PortMappings,
	}

	// Parse the ENI MAC address.
	if config.ENIMACAddress != "" {
		netConfig.ENIMACAddress, err = net.ParseMAC(config.ENIMACAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid ENIMACAddress %s", config.ENIMACAddress)
		}
	}

	// Parse the optional ENI IP addresses.
	for _, eniIPString := range config.ENIIPAddresses {
		eniIP, err := vpc.GetIPAddressFromString(eniIPString)
		if err != nil {
			return nil, fmt.Errorf("invalid ENIIPAddress %s", eniIPString)
		}
		netConfig.ENIIPAddresses = append(netConfig.ENIIPAddresses, *eniIP)
	}

	// Parse the optional VPC CIDR blocks.
	if config.VPCCIDRs != nil {
		for _, cidrString := range config.VPCCIDRs {
			_, cidr, err := net.ParseCIDR(cidrString)
			if err != nil {
				return nil, fmt.Errorf("invalid VPCCIDR %s", cidrString)
			}
			netConfig.VPCCIDRs = append(netConfig.VPCCIDRs, *cidr)
		}
	}

	// Parse the bridge type.
	if config.BridgeType != BridgeTypeL2 && config.BridgeType != BridgeTypeL3 {
		return nil, fmt.Errorf("invalid BridgeType %s", config.BridgeType)
	}

	// Parse the optional IP addresses.
	for _, ipString := range config.IPAddresses {
		ipAddress, err := vpc.GetIPAddressFromString(ipString)
		if err != nil {
			return nil, fmt.Errorf("invalid IPAddress %s", ipString)
		}
		netConfig.IPAddresses = append(netConfig.IPAddresses, *ipAddress)
	}

	// Parse the optional gateway IP address.
	if config.GatewayIPAddress != "" {
		netConfig.GatewayIPAddress = net.ParseIP(config.GatewayIPAddress)
		if netConfig.GatewayIPAddress == nil {
			return nil, fmt.Errorf("invalid GatewayIPAddress %s", config.GatewayIPAddress)
		}
	}

	// Parse the interface type.
	if config.InterfaceType != IfTypeVETH && config.InterfaceType != IfTypeTAP {
		return nil, fmt.Errorf("invalid InterfaceType %s", config.InterfaceType)
	}

	// Parse the optional TAP user ID.
	if config.TapUserID != "" {
		netConfig.TapUserID, err = strconv.Atoi(config.TapUserID)
		if err != nil {
			return nil, fmt.Errorf("invalid TapUserID %s", config.TapUserID)
		}
	}

	// Parse orchestrator-specific configuration.
	if strings.Contains(args.Args, "K8S") {
		netConfig.Kubernetes = &KubernetesConfig{
			ServiceCIDR: config.ServiceCIDR,
		}

		err = parseKubernetesArgs(&netConfig, args, isAddCmd)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Kubernetes args: %v", err)
		}
	}

	// Validation complete. Return the parsed NetConfig object.
	log.Debugf("Created NetConfig: %+v", netConfig)
	return &netConfig, nil
}
