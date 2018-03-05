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
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
)

// NetConfig defines the network configuration for the vpc-branch-eni plugin.
type NetConfig struct {
	cniTypes.NetConf
	TrunkName        string `json:"trunkName"`
	BranchMACAddress string `json:"branchMACAddress"`
	BranchVlanID     string `json:"branchVlanID"`
}

// New creates a new NetConfig object by parsing the given CNI arguments.
func New(args *cniSkel.CmdArgs) (*NetConfig, error) {
	var config NetConfig
	if err := json.Unmarshal(args.StdinData, &config); err != nil {
		return nil, fmt.Errorf("Failed to parse network config: %v", err)
	}

	// Validate if all the required fields are present.
	if config.TrunkName == "" {
		return nil, fmt.Errorf("Missing required parameter trunkName")
	}
	if config.BranchMACAddress == "" {
		return nil, fmt.Errorf("Missing required parameter branchMACAddress")
	}
	if config.BranchVlanID == "" {
		return nil, fmt.Errorf("Missing required parameter branchVlanID")
	}

	// Validate if the MAC address is valid.
	if _, err := net.ParseMAC(config.BranchMACAddress); err != nil {
		return nil, fmt.Errorf("Invalid branchMACAddress %s", config.BranchMACAddress)
	}

	// Validation complete. Return the parsed config object.
	log.Debugf("Created NetConfig: %+v", config)
	return &config, nil
}
