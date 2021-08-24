// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

// NetConfig defines the network configuration for the vpc-tunnel plugin.
type NetConfig struct {
	cniTypes.NetConf
	DestinationIPAddress net.IP
	VNI                  string
	DestinationPort      uint16
	Primary              bool
	IPAddresses          []net.IPNet
	GatewayIPAddress     net.IP
	InterfaceType        string
	Tap                  *TAPConfig
}

// netConfigJSON defines the network configuration JSON file format for the vpc-tunnel plugin.
type netConfigJSON struct {
	cniTypes.NetConf
	DestinationIPAddress string   `json:"destinationIPAddress"`
	VNI                  string   `json:"vni"`
	DestinationPort      string   `json:"destinationPort"`
	Primary              bool     `json:"primary"`
	IPAddresses          []string `json:"ipAddresses"`
	GatewayIPAddress     string   `json:"gatewayIPAddress"`
	InterfaceType        string   `json:"interfaceType"`
	Uid                  string   `json:"uid"`
	Gid                  string   `json:"gid"`
}

// TAPConfig defines a TAP interface configuration.
type TAPConfig struct {
	Uid    int
	Gid    int
	Queues int
}

// pcArgs defines the per-container arguments passed in CNI_ARGS environment variable.
type pcArgs struct {
	cniTypes.CommonArgs
	DestinationIPAddress cniTypes.UnmarshallableString
	VNI                  cniTypes.UnmarshallableString
	DestinationPort      cniTypes.UnmarshallableString
	IPAddresses          cniTypes.UnmarshallableString
	GatewayIPAddress     cniTypes.UnmarshallableString
	Primary              cniTypes.UnmarshallableString
}

const (
	// Interface type values.
	IfTypeGeneve = "geneve"
	IfTypeTAP    = "tap"

	// Default number of queues to use with TAP interfaces.
	defaultTapQueues = 1

	// Whether the plugin ignores unknown per-container arguments.
	ignoreUnknown = true
)

// New creates a new NetConfig object by parsing the given CNI arguments.
func New(args *cniSkel.CmdArgs) (*NetConfig, error) {
	// Parse network configuration.
	var configJSON netConfigJSON
	err := json.Unmarshal(args.StdinData, &configJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse network configJSON: %v", err)
	}

	// Parse optional per-container arguments.
	if args.Args != "" {
		var pca pcArgs
		pca.IgnoreUnknown = ignoreUnknown

		if err := cniTypes.LoadArgs(args.Args, &pca); err != nil {
			return nil, fmt.Errorf("failed to parse per-container args: %v", err)
		}

		// Per-container arguments override the ones from network configuration.
		if pca.DestinationIPAddress != "" {
			configJSON.DestinationIPAddress = string(pca.DestinationIPAddress)
		}
		if pca.VNI != "" {
			configJSON.VNI = string(pca.VNI)
		}
		if pca.DestinationPort != "" {
			configJSON.DestinationPort = string(pca.DestinationPort)
		}
		if pca.IPAddresses != "" {
			configJSON.IPAddresses = strings.Split(string(pca.IPAddresses), ",")
		}
		if pca.GatewayIPAddress != "" {
			configJSON.GatewayIPAddress = string(pca.GatewayIPAddress)
		}
		if pca.Primary != "" {
			configJSON.Primary, err = strconv.ParseBool(string(pca.Primary))
			if err != nil {
				return nil, fmt.Errorf("invalid value for primary flag")
			}
		}
	}

	// Set defaults.
	if configJSON.InterfaceType == "" {
		configJSON.InterfaceType = IfTypeTAP
	}

	// Validate if all the required fields are present.
	if configJSON.DestinationIPAddress == "" {
		return nil, fmt.Errorf("missing required parameter destinationIPAddress")
	}
	if configJSON.VNI == "" {
		return nil, fmt.Errorf("missing required parameter vni")
	}
	if configJSON.DestinationPort == "" {
		return nil, fmt.Errorf("missing required parameter destination port")
	}

	// Under TAP mode, UID and GID are required to set TAP ownership.
	if configJSON.InterfaceType == IfTypeTAP {
		if configJSON.Uid == "" {
			return nil, fmt.Errorf("missing required parameter uid")
		}
		if configJSON.Gid == "" {
			return nil, fmt.Errorf("missing required parameter gid")
		}
	}

	// Populate NetConfig.
	netConfig := NetConfig{
		NetConf:       configJSON.NetConf,
		InterfaceType: configJSON.InterfaceType,
		Primary:       configJSON.Primary,
	}

	// Parse the tunnel ip address.
	if configJSON.DestinationIPAddress != "" {
		netConfig.DestinationIPAddress = net.ParseIP(configJSON.DestinationIPAddress)
		if err != nil {
			return nil, fmt.Errorf("invalid destinationIPAddress %s", configJSON.DestinationIPAddress)
		}
	}

	// Extract the VNI.
	netConfig.VNI = configJSON.VNI

	// Parse the Destination port address.
	dPort, err := strconv.Atoi(configJSON.DestinationPort)
	if err != nil {
		return nil, fmt.Errorf("invalid destination port %s", configJSON.DestinationPort)
	}
	netConfig.DestinationPort = uint16(dPort)

	// Parse IP addresses. These can be IPv4 or IPv6 addresses and are optional for some
	// setups like TAP interfaces where the IP addresses are assigned through other means.
	for _, s := range configJSON.IPAddresses {
		addr, err := vpc.GetIPAddressFromString(s)
		if err != nil {
			return nil, fmt.Errorf("invalid ipAddress %s", s)
		}
		netConfig.IPAddresses = append(netConfig.IPAddresses, *addr)
	}

	// Parse gateway IP addresses.
	addr := net.ParseIP(configJSON.GatewayIPAddress)
	if addr == nil {
		return nil, fmt.Errorf("invalid gatewayIPAddress %s", configJSON.GatewayIPAddress)
	}
	netConfig.GatewayIPAddress = addr

	// Parse the TAP interface owner UID and GID.
	if configJSON.InterfaceType == IfTypeTAP {
		netConfig.Tap = &TAPConfig{
			Queues: defaultTapQueues,
		}

		if configJSON.Uid != "" {
			netConfig.Tap.Uid, err = strconv.Atoi(configJSON.Uid)
			if err != nil {
				return nil, fmt.Errorf("invalid uid %s", configJSON.Uid)
			}
		}

		if configJSON.Gid != "" {
			netConfig.Tap.Gid, err = strconv.Atoi(configJSON.Gid)
			if err != nil {
				return nil, fmt.Errorf("invalid gid %s", configJSON.Gid)
			}
		}
	}

	// Validation complete. Return the parsed NetConfig object.
	log.Debugf("Created NetConfig: %+v", netConfig)
	return &netConfig, nil
}
