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

// NetConfig defines the network configuration for the vpc-branch-pat-eni plugin.
type NetConfig struct {
	cniTypes.NetConf
	TrunkName        string
	TrunkMACAddress  net.HardwareAddr
	BranchVlanID     int
	BranchMACAddress net.HardwareAddr
	BranchIPAddress  net.IPNet
	Uid              int
	Gid              int
	CleanupPATNetNS  bool
}

// netConfigJSON defines the network configuration JSON file format for the vpc-branch-pat-eni plugin.
type netConfigJSON struct {
	cniTypes.NetConf
	TrunkName        string `json:"trunkName"`
	TrunkMACAddress  string `json:"trunkMACAddress"`
	BranchVlanID     string `json:"branchVlanID"`
	BranchMACAddress string `json:"branchMACAddress"`
	BranchIPAddress  string `json:"branchIPAddress"`
	Uid              string `json:"uid"`
	Gid              string `json:"gid"`
	CleanupPATNetNS  bool   `json:"cleanupPATNetNS"`
}

// New creates a new NetConfig object by parsing the given CNI arguments.
func New(args *cniSkel.CmdArgs, isAdd bool) (*NetConfig, error) {
	var config netConfigJSON
	err := json.Unmarshal(args.StdinData, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse network config: %v", err)
	}

	// Validate if all the required fields are present.
	if config.TrunkName == "" && config.TrunkMACAddress == "" {
		return nil, fmt.Errorf("missing required parameter trunkName or trunkMACAddress")
	}
	if config.BranchVlanID == "" {
		return nil, fmt.Errorf("missing required parameter branchVlanID")
	}
	if isAdd && config.BranchMACAddress == "" {
		return nil, fmt.Errorf("missing required parameter branchMACAddress")
	}

	// Populate NetConfig.
	netConfig := NetConfig{
		NetConf:         config.NetConf,
		TrunkName:       config.TrunkName,
		CleanupPATNetNS: config.CleanupPATNetNS,
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

	// Parse the optional branch MAC address.
	if config.BranchMACAddress != "" {
		netConfig.BranchMACAddress, err = net.ParseMAC(config.BranchMACAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid branchMACAddress %s", config.BranchMACAddress)
		}
	}

	// Parse the optional branch IP address.
	if config.BranchIPAddress != "" {
		ipAddr, err := vpc.GetIPAddressFromString(config.BranchIPAddress)
		netConfig.BranchIPAddress = *ipAddr
		if err != nil {
			return nil, fmt.Errorf("invalid branchIPAddress %s", config.BranchIPAddress)
		}
	}

	// Parse the optional TAP interface UID and GID.
	if config.Uid != "" {
		netConfig.Uid, err = strconv.Atoi(config.Uid)
		if err != nil {
			return nil, fmt.Errorf("invalid UID %s", config.Uid)
		}
	}

	if config.Gid != "" {
		netConfig.Gid, err = strconv.Atoi(config.Gid)
		if err != nil {
			return nil, fmt.Errorf("invalid GID %s", config.Gid)
		}
	}

	// Validation complete. Return the parsed NetConfig object.
	log.Debugf("Created NetConfig: %+v", config)
	return &netConfig, nil
}
