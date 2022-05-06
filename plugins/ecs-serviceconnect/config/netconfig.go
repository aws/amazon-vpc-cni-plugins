// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
	utils "github.com/aws/amazon-vpc-cni-plugins/plugins/utils/config"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/coreos/go-iptables/iptables"
	"strconv"
	"strings"
)

type NetworkMode string

const (
	// TODO: This is for experimenting with different configs. Will be changed to bridge
	BRIDGE_DNAT   NetworkMode = "bridge_dnat"
	BRIDGE_TPROXY NetworkMode = "bridge_tproxy"
	AWSVPC        NetworkMode = "awsvpc"
)

// NetConfig defines the network configuration for the ecs-serviceconnect cni plugin.
type NetConfig struct {
	cniTypes.NetConf
	IngressRedirectToListenerPortMap map[string]string
	EgressPort                       int
	EgressIPV4CIDR                   string
	EgressIPV6CIDR                   string
	IPProtocols                      []iptables.Protocol
	Mode                             NetworkMode // To be used in future
}

// netConfigJSON defines the network configuration JSON file format for the ecs-serviceconnect cni plugin.
type netConfigJSON struct {
	cniTypes.NetConf
	IngressConfig []IngressConfigJSONEntry `json:"ingressConfig"`
	EgressConfig  *EgressConfigJSON        `json:"egressConfig"`
	NetworkConfig *NetworkMode             `json:"networkMode"`
	EnableIPv6    bool                     `json:"enableIPv6"`
}

// IngressConfigJSONEntry defines the ingress network config in JSON format for the ecs-serviceconnect cni plugin.
type IngressConfigJSONEntry struct {
	ListenerPort  int `json:"listenerPort"`
	InterceptPort int `json:"interceptPort,omitempty"`
}

// EgressConfigJSON defines the egress network config in JSON format for the ecs-serviceconnect cni plugin.
type EgressConfigJSON struct {
	ListenerPort int            `json:"listenerPort"`
	VIP          *VIPConfigJSON `json:"vip"`
}

// VIPConfigJSON defines the EgressVIP network config in JSON format for the ecs-serviceconnect cni plugin.
type VIPConfigJSON struct {
	IPV4CIDR string `json:"ipv4Cidr,omitempty"`
	IPV6CIDR string `json:"ipv6Cidr,omitempty"`
}

// New creates a new NetConfig object by parsing the given CNI arguments.
func New(args *cniSkel.CmdArgs) (*NetConfig, error) {
	// Parse Json configuration.
	var config netConfigJSON
	if err := json.Unmarshal(args.StdinData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse network config: %v", err)
	}

	// Validate the configuration.
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	// Parse ingress and construct a listener map
	ingressRedirectToListenerPortMap := make(map[string]string)
	for _, s := range config.IngressConfig {
		if s.InterceptPort != 0 {
			ingressRedirectToListenerPortMap[strconv.Itoa(s.ListenerPort)] = strconv.Itoa(s.InterceptPort)
		}
	}
	// Parse egress
	egressPort := 0
	var egressIPV4CIDR, egressIPV6CIDR string
	if config.EgressConfig != nil {
		egressPort = config.EgressConfig.ListenerPort
		egressIPV4CIDR = config.EgressConfig.VIP.IPV4CIDR
		egressIPV6CIDR = config.EgressConfig.VIP.IPV6CIDR
	}

	// Populate NetConfig.
	netConfig := NetConfig{
		NetConf:                          config.NetConf,
		IngressRedirectToListenerPortMap: ingressRedirectToListenerPortMap,
		EgressPort:                       egressPort,
		EgressIPV4CIDR:                   egressIPV4CIDR,
		EgressIPV6CIDR:                   egressIPV6CIDR,
		IPProtocols:                      getIPProtocols(config),
		Mode:                             *config.NetworkConfig,
	}
	return &netConfig, nil
}

// validateConfig validates the given network configuration.
func validateConfig(config netConfigJSON) error {
	if len(config.IngressConfig) == 0 && config.EgressConfig == nil {
		return fmt.Errorf("either IngressConfig or EgressConfig must be present")
	}
	if config.NetworkConfig == nil {
		return fmt.Errorf("missing required parameter: NetworkConfig")
	}

	if err := validateIngressConfig(config); err != nil {
		return err
	}
	if config.EgressConfig != nil {
		if err := validateEgressConfig(config); err != nil {
			return err
		}
	}

	// Validate Network Config
	return validateNetworkConfig(config)
}

// validateIngressConfig validates Ingress Configuration
func validateIngressConfig(config netConfigJSON) error {
	for _, s := range config.IngressConfig {
		// verify that the ports are valid
		if err := utils.IsValidPortRange(s.ListenerPort); err != nil {
			return err
		}
		if s.InterceptPort != 0 {
			return utils.IsValidPortRange(s.InterceptPort)
		}
	}
	return nil
}

// validateEgressConfig validates the egress configuration
func validateEgressConfig(config netConfigJSON) error {
	// verify that the port is valid
	if err := utils.IsValidPortRange(config.EgressConfig.ListenerPort); err != nil {
		return err
	}

	// verify that the egress vip is a valid CIDR
	var egressVIPConfig = config.EgressConfig.VIP
	if egressVIPConfig == nil {
		return fmt.Errorf("missing required parameter: EgressConfig VIP")
	}
	if egressVIPConfig.IPV4CIDR == "" {
		return fmt.Errorf("missing required parameter: EgressConfig IPV4 VIP CIDR Address")
	}

	trimCIDR := strings.TrimSpace(egressVIPConfig.IPV4CIDR)
	if proto, valid := utils.IsValidCIDR(trimCIDR); !valid || proto != iptables.ProtocolIPv4 {
		return fmt.Errorf("invalid parameter: EgressConfig IPv4 CIDR Address")
	}

	if egressVIPConfig.IPV6CIDR != "" {
		trimCIDR := strings.TrimSpace(egressVIPConfig.IPV6CIDR)
		if proto, valid := utils.IsValidCIDR(trimCIDR); !valid || proto != iptables.ProtocolIPv6 {
			return fmt.Errorf("invalid parameter: EgressConfig IPv6 CIDR Address")
		}
	}
	return nil
}

// validateNetworkConfig validates the Network Configuration
func validateNetworkConfig(config netConfigJSON) error {
	switch *config.NetworkConfig {
	case AWSVPC, BRIDGE_DNAT, BRIDGE_TPROXY:
		return nil
	}
	return fmt.Errorf("invalid value for NetworkConfig")
}

// getIPProtocols returns the IP protocols that need to be handled for the config
func getIPProtocols(config netConfigJSON) []iptables.Protocol {
	var ipProtos []iptables.Protocol
	ipProtos = append(ipProtos, iptables.ProtocolIPv4)
	if config.EnableIPv6 {
		ipProtos = append(ipProtos, iptables.ProtocolIPv6)
	}
	return ipProtos
}
