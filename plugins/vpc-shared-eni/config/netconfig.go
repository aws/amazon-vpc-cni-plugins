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
	ENIName          string `json:"eniName"`
	ENIMACAddress    string `json:"eniMACAddress"`
	ENIIPAddress     string `json:"eniIPAddress"`
	BridgeNetNSPath  string `json:"bridgeNetNSPath"`
	IPAddress        string `json:"ipAddress"`
	GatewayIPAddress string `json:"gatewayIPAddress"`
	InterfaceType    string `json:"interfaceType"`
	TapUserID        string `json:"tapUserID"`
	ServiceSubnet    string `json:"serviceSubnet"`
}

const (
	// Bridge network namespace defaults to the host network namespace (empty string),
	// or more precisely, whichever namespace the CNI plugin is running in.
	defaultBridgeNetNSPath = ""

	// Interface type values.
	IfTypeVETH = "veth"
	IfTypeTAP  = "tap"
)

// New creates a new NetConfig object by parsing the given CNI arguments.
func New(args *cniSkel.CmdArgs) (*NetConfig, error) {
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
		BridgeNetNSPath: config.BridgeNetNSPath,
		Kubernetes: KubernetesConfig{
			ServiceSubnet: config.ServiceSubnet,
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

	// Parse the optional TAP user ID.
	if config.TapUserID != "" {
		netConfig.TapUserID, err = strconv.Atoi(config.TapUserID)
		if err != nil {
			return nil, fmt.Errorf("invalid TapUserID %s", config.TapUserID)
		}
	}

	// Parse orchestrator-specific configuration.
	if strings.Contains(args.Args, "K8S") {
		err = parseKubernetesArgs(&netConfig, args)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Kubernetes args: %v", err)
		}
	}

	// Validation complete. Return the parsed NetConfig object.
	log.Debugf("Created NetConfig: %+v", netConfig)
	return &netConfig, nil
}
