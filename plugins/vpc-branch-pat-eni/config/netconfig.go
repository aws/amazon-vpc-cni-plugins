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

	log "github.com/cihub/seelog"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
)

// NetConfig defines the network configuration for the vpc-branch-pat-eni plugin.
type NetConfig struct {
	types.NetConf
	TrunkName        string `json:"trunkName"`
	TrunkMACAddress  string `json:"trunkMACAddress"`
	BranchVlanID     string `json:"branchVlanID"`
	BranchMACAddress string `json:"branchMACAddress"`
	BranchIPAddress  string `json:"branchIPAddress"`
	UserName         string `json:"userName"`
	CleanupPATNetNS  bool   `json:"cleanupPATNetNS"`
}

// New creates a new NetConfig object by parsing the given CNI arguments.
func New(args *skel.CmdArgs, isAdd bool) (*NetConfig, error) {
	var config NetConfig
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

	// Parse the trunk MAC address.
	if config.TrunkMACAddress != "" {
		_, err = net.ParseMAC(config.TrunkMACAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid trunkMACAddress %s", config.TrunkMACAddress)
		}
	}

	// Parse the branch MAC address.
	if config.BranchMACAddress != "" {
		_, err = net.ParseMAC(config.BranchMACAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid branchMACAddress %s", config.BranchMACAddress)
		}
	}

	// Validate if the IPv4 address is valid.
	if config.BranchIPAddress != "" {
		if _, _, err := net.ParseCIDR(config.BranchIPAddress); err != nil {
			return nil, fmt.Errorf("invalid branchIPAddress %s", config.BranchIPAddress)
		}
	}

	// Validation complete. Return the parsed config object.
	log.Debugf("Created NetConfig: %+v", config)
	return &config, nil
}

// isValidIPv4Address returns whether the given string is a valid IPv4 address.
func isValidIPV4Address(address string) bool {
	ip := net.ParseIP(address)
	if ip == nil || ip.To4() == nil {
		return false
	}
	return true
}
