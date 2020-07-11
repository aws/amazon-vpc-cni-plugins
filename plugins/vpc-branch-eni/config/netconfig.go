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

// NetConfig defines the network configuration for the vpc-branch-eni plugin.
type NetConfig struct {
	cniTypes.NetConf
	TrunkName          string
	TrunkMACAddress    net.HardwareAddr
	BranchVlanID       int
	BranchMACAddress   net.HardwareAddr
	IPAddresses        []net.IPNet
	GatewayIPAddresses []net.IP
	BlockIMDS          bool
	InterfaceType      string
	Tap                *TAPConfig
}

// TAPConfig defines a TAP interface configuration.
type TAPConfig struct {
	Uid    int
	Gid    int
	Queues int
}

// netConfigJSON defines the network configuration JSON file format for the vpc-branch-eni plugin.
type netConfigJSON struct {
	cniTypes.NetConf
	TrunkName          string   `json:"trunkName"`
	TrunkMACAddress    string   `json:"trunkMACAddress"`
	BranchVlanID       string   `json:"branchVlanID"`
	BranchMACAddress   string   `json:"branchMACAddress"`
	IPAddresses        []string `json:"ipAddresses"`
	GatewayIPAddresses []string `json:"gatewayIPAddresses"`
	BlockIMDS          bool     `json:"blockInstanceMetadata"`
	InterfaceType      string   `json:"interfaceType"`
	Uid                string   `json:"uid"`
	Gid                string   `json:"gid"`
}

// pcArgs defines the per-container arguments passed in CNI_ARGS environment variable.
type pcArgs struct {
	cniTypes.CommonArgs
	BranchVlanID       cniTypes.UnmarshallableString
	BranchMACAddress   cniTypes.UnmarshallableString
	IPAddresses        cniTypes.UnmarshallableString
	GatewayIPAddresses cniTypes.UnmarshallableString
}

const (
	// Interface type values.
	IfTypeVLAN    = "vlan"
	IfTypeTAP     = "tap"
	IfTypeMACVTAP = "macvtap"

	// Default number of queues to use with TAP interfaces.
	defaultTapQueues = 1

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
		if pca.IPAddresses != "" {
			config.IPAddresses = strings.Split(string(pca.IPAddresses), ",")
		}
		if pca.GatewayIPAddresses != "" {
			config.GatewayIPAddresses = strings.Split(string(pca.GatewayIPAddresses), ",")
		}
	}

	// Set defaults.
	if config.InterfaceType == "" {
		config.InterfaceType = IfTypeTAP
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

	// Under TAP mode, UID and GID are required to set TAP ownership.
	if config.InterfaceType == IfTypeTAP {
		if config.Uid == "" {
			return nil, fmt.Errorf("missing required parameter uid")
		}
		if config.Gid == "" {
			return nil, fmt.Errorf("missing required parameter gid")
		}
	}

	// Populate NetConfig.
	netConfig := NetConfig{
		NetConf:       config.NetConf,
		TrunkName:     config.TrunkName,
		BlockIMDS:     config.BlockIMDS,
		InterfaceType: config.InterfaceType,
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

	// Parse branch IP addresses. These can be IPv4 or IPv6 addresses and are optional for some
	// setups like TAP interfaces where the IP addresses are assigned through other means.
	for _, s := range config.IPAddresses {
		addr, err := vpc.GetIPAddressFromString(s)
		if err != nil {
			return nil, fmt.Errorf("invalid ipAddress %s", s)
		}
		netConfig.IPAddresses = append(netConfig.IPAddresses, *addr)
	}

	// Parse optional gateway IP addresses.
	for _, s := range config.GatewayIPAddresses {
		addr := net.ParseIP(s)
		if addr == nil {
			return nil, fmt.Errorf("invalid gatewayIPAddress %s", s)
		}
		netConfig.GatewayIPAddresses = append(netConfig.GatewayIPAddresses, addr)
	}

	// Parse the TAP interface owner UID and GID.
	if config.InterfaceType == IfTypeTAP {
		netConfig.Tap = &TAPConfig{
			Queues: defaultTapQueues,
		}

		if config.Uid != "" {
			netConfig.Tap.Uid, err = strconv.Atoi(config.Uid)
			if err != nil {
				return nil, fmt.Errorf("invalid uid %s", config.Uid)
			}
		}

		if config.Gid != "" {
			netConfig.Tap.Gid, err = strconv.Atoi(config.Gid)
			if err != nil {
				return nil, fmt.Errorf("invalid gid %s", config.Gid)
			}
		}
	}

	// Validation complete. Return the parsed NetConfig object.
	log.Debugf("Created NetConfig: %+v", netConfig)
	return &netConfig, nil
}
