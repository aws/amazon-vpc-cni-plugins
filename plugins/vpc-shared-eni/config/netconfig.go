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

// NetConfig defines the network configuration for the vpc-shared-eni plugin.
type NetConfig struct {
	cniTypes.NetConf
	ENIName          string
	ENIMACAddress    net.HardwareAddr
	ENIIPAddress     *net.IPNet
	VPCCIDRs         []net.IPNet
	BridgeType       string
	BridgeNetNSPath  string
	IPAddress        *net.IPNet
	GatewayIPAddress net.IP
	InterfaceType    string
	TapUserID        int
	Kubernetes       KubernetesConfig
}

// netConfigJSON defines the network configuration JSON file format for the vpc-shared-eni plugin.
type netConfigJSON struct {
	cniTypes.NetConf
	ENIName          string   `json:"eniName"`
	ENIMACAddress    string   `json:"eniMACAddress"`
	ENIIPAddress     string   `json:"eniIPAddress"`
	VPCCIDRs         []string `json:"vpcCIDRs"`
	BridgeType       string   `json:"bridgeType"`
	BridgeNetNSPath  string   `json:"bridgeNetNSPath"`
	IPAddress        string   `json:"ipAddress"`
	GatewayIPAddress string   `json:"gatewayIPAddress"`
	InterfaceType    string   `json:"interfaceType"`
	TapUserID        string   `json:"tapUserID"`
	ServiceCIDR      string   `json:"serviceCIDR"`
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
		Kubernetes: KubernetesConfig{
			ServiceCIDR: config.ServiceCIDR,
		},
	}

	// Parse the ENI MAC address.
	if config.ENIMACAddress != "" {
		netConfig.ENIMACAddress, err = net.ParseMAC(config.ENIMACAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid ENIMACAddress %s", config.ENIMACAddress)
		}
	}

	// Parse the optional ENI IP address.
	if config.ENIIPAddress != "" {
		netConfig.ENIIPAddress, err = vpc.GetIPAddressFromString(config.ENIIPAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid ENIIPAddress %s", config.ENIIPAddress)
		}
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

	// Parse the optional IP address.
	if config.IPAddress != "" {
		netConfig.IPAddress, err = vpc.GetIPAddressFromString(config.IPAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid IPAddress %s", config.IPAddress)
		}
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
		err = parseKubernetesArgs(&netConfig, args, isAddCmd)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Kubernetes args: %v", err)
		}
	}

	// Validation complete. Return the parsed NetConfig object.
	log.Debugf("Created NetConfig: %+v", netConfig)
	return &netConfig, nil
}
