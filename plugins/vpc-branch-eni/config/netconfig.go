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

	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
)

// NetConfig defines the network configuration for the vpc-branch-eni plugin.
type NetConfig struct {
	cniTypes.NetConf
	TrunkName              string
	TrunkMACAddress        net.HardwareAddr
	BranchVlanID           int
	BranchMACAddress       net.HardwareAddr
	BranchIPAddress        *net.IPNet
	BranchGatewayIPAddress net.IP
	InterfaceType          string
	UserName               string
	BlockIMDS              bool
}

// netConfigJSON defines the network configuration JSON file format for the vpc-branch-eni plugin.
type netConfigJSON struct {
	cniTypes.NetConf
	TrunkName              string `json:"trunkName"`
	TrunkMACAddress        string `json:"trunkMACAddress"`
	BranchVlanID           string `json:"branchVlanID"`
	BranchMACAddress       string `json:"branchMACAddress"`
	BranchIPAddress        string `json:"branchIPAddress"`
	BranchGatewayIPAddress string `json:"branchGatewayIPAddress"`
	InterfaceType          string `json:"interfaceType"`
	UserName               string `json:"userName"`
	BlockIMDS              bool   `json:"blockInstanceMetadata"`
}

// pcArgs defines the per-container arguments passed in CNI_ARGS environment variable.
type pcArgs struct {
	cniTypes.CommonArgs
	BranchVlanID     cniTypes.UnmarshallableString
	BranchMACAddress cniTypes.UnmarshallableString
	BranchIPAddress  cniTypes.UnmarshallableString
}

const (
	// Interface type values.
	IfTypeVLAN    = "vlan"
	IfTypeTAP     = "tap"
	IfTypeMACVTAP = "macvtap"

	// Whether the plugin ignores unknown per-container arguments.
	ignoreUnknown = true
)

// New creates a new NetConfig object by parsing the given CNI arguments.
func New(args *cniSkel.CmdArgs) (*NetConfig, error) {
	// Parse network configuration.
	var config netConfigJSON
	err := json.Unmarshal(args.StdinData, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse network config: %v", err)
	}

	// Parse optional per-container arguments.
	if args.Args != "" {
		var pca pcArgs
		pca.IgnoreUnknown = ignoreUnknown

		if err := cniTypes.LoadArgs(args.Args, &pca); err != nil {
			return nil, fmt.Errorf("failed to parse per-container args: %v", err)
		}

		// Per-container arguments override the ones from network configuration.
		if pca.BranchVlanID != "" {
			config.BranchVlanID = string(pca.BranchVlanID)
		}
		if pca.BranchMACAddress != "" {
			config.BranchMACAddress = string(pca.BranchMACAddress)
		}
		if pca.BranchIPAddress != "" {
			config.BranchIPAddress = string(pca.BranchIPAddress)
		}
	}

	// Validate if all the required fields are present.
	if config.TrunkName == "" && config.TrunkMACAddress == "" {
		return nil, fmt.Errorf("missing required parameter trunkName or trunkMACAddress")
	}
	if config.BranchVlanID == "" {
		return nil, fmt.Errorf("missing required parameter branchVlanID")
	}
	if config.BranchMACAddress == "" {
		return nil, fmt.Errorf("missing required parameter branchMACAddress")
	}

	// Set defaults.
	if config.InterfaceType == "" {
		config.InterfaceType = IfTypeTAP
	}

	// Populate NetConfig.
	netConfig := NetConfig{
		NetConf:       config.NetConf,
		TrunkName:     config.TrunkName,
		InterfaceType: config.InterfaceType,
		UserName:      config.UserName,
		BlockIMDS:     config.BlockIMDS,
	}

	// Parse the trunk MAC address.
	if config.TrunkMACAddress != "" {
		netConfig.TrunkMACAddress, err = net.ParseMAC(config.TrunkMACAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid trunkMACAddress %s", config.TrunkMACAddress)
		}
	}

	// Parse the branch VLAN ID.
	netConfig.BranchVlanID, err = strconv.Atoi(config.BranchVlanID)
	if err != nil {
		return nil, fmt.Errorf("invalid branchVlanID %s", config.BranchVlanID)
	}

	// Parse the branch MAC address.
	netConfig.BranchMACAddress, err = net.ParseMAC(config.BranchMACAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid branchMACAddress %s", config.BranchMACAddress)
	}

	// Parse the optional branch IP address.
	if config.BranchIPAddress != "" {
		netConfig.BranchIPAddress, err = vpc.GetIPAddressFromString(config.BranchIPAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid branchIPAddress %s", config.BranchIPAddress)
		}
	}

	// Parse the optional gateway IP address.
	if config.BranchGatewayIPAddress != "" {
		netConfig.BranchGatewayIPAddress = net.ParseIP(config.BranchGatewayIPAddress)
		if netConfig.BranchGatewayIPAddress == nil {
			return nil, fmt.Errorf("invalid branchGatewayIPAddress %s", config.BranchGatewayIPAddress)
		}
	}

	// Validation complete. Return the parsed NetConfig object.
	log.Debugf("Created NetConfig: %+v", netConfig)
	return &netConfig, nil
}
