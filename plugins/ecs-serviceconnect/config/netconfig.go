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
	"strconv"
	"strings"

	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"

	"github.com/coreos/go-iptables/iptables"
)

// NetConfig defines the network configuration for the ecs-serviceconnect CNI plugin.
type NetConfig struct {
	cniTypes.NetConf
	IngressListenerToInterceptPortMap map[string]string
	EgressPort                        int
	EgressIPv4CIDR                    string
	EgressIPv6CIDR                    string
	IPProtocols                       []iptables.Protocol
}

// netConfigJSON defines the network configuration JSON file format for the ecs-serviceconnect CNI plugin.
type netConfigJSON struct {
	cniTypes.NetConf
	IngressConfig []ingressConfigJSONEntry `json:"ingressConfig"`
	EgressConfig  *egressConfigJSON        `json:"egressConfig"`
	EnableIPv6    bool                     `json:"enableIPv6"`
}

// ingressConfigJSONEntry defines the ingress network config in JSON format for the ecs-serviceconnect CNI plugin.
type ingressConfigJSONEntry struct {
	ListenerPort  int `json:"listenerPort"`
	InterceptPort int `json:"interceptPort,omitempty"`
}

// egressConfigJSON defines the egress network config in JSON format for the ecs-serviceconnect CNI plugin.
type egressConfigJSON struct {
	ListenerPort int            `json:"listenerPort"`
	VIP          *vipConfigJSON `json:"vip"`
}

// vipConfigJSON defines the EgressVIP network config in JSON format for the ecs-serviceconnect CNI plugin.
type vipConfigJSON struct {
	IPv4CIDR string `json:"ipv4Cidr,omitempty"`
	IPv6CIDR string `json:"ipv6Cidr,omitempty"`
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
	ingressListenerToInterceptPortMap := make(map[string]string)
	for _, s := range config.IngressConfig {
		if s.InterceptPort != 0 {
			ingressListenerToInterceptPortMap[strconv.Itoa(s.ListenerPort)] = strconv.Itoa(s.InterceptPort)
		}
	}
	// Parse egress
	egressPort := 0
	var egressIPv4CIDR, egressIPv6CIDR string
	if config.EgressConfig != nil {
		egressPort = config.EgressConfig.ListenerPort
		egressIPv4CIDR = config.EgressConfig.VIP.IPv4CIDR
		egressIPv6CIDR = config.EgressConfig.VIP.IPv6CIDR
	}

	// Populate NetConfig.
	netConfig := NetConfig{
		NetConf:                           config.NetConf,
		IngressListenerToInterceptPortMap: ingressListenerToInterceptPortMap,
		EgressPort:                        egressPort,
		EgressIPv4CIDR:                    egressIPv4CIDR,
		EgressIPv6CIDR:                    egressIPv6CIDR,
		IPProtocols:                       getIPProtocols(config),
	}
	return &netConfig, nil
}

// validateConfig validates the given network configuration.
func validateConfig(config netConfigJSON) error {
	if len(config.IngressConfig) == 0 && config.EgressConfig == nil {
		return fmt.Errorf("either IngressConfig or EgressConfig must be present")
	}

	if err := validateIngressConfig(config); err != nil {
		return err
	}
	if config.EgressConfig != nil {
		if err := validateEgressConfig(config); err != nil {
			return err
		}
	}
	return nil
}

// validateIngressConfig validates Ingress Configuration
func validateIngressConfig(config netConfigJSON) error {
	for _, s := range config.IngressConfig {
		// verify that the ports are valid
		if err := vpc.ValidatePortRange(s.ListenerPort); err != nil {
			return err
		}
		if s.InterceptPort != 0 {
			return vpc.ValidatePortRange(s.InterceptPort)
		}
	}
	return nil
}

// validateEgressConfig validates the egress configuration
func validateEgressConfig(config netConfigJSON) error {
	// verify that the port is valid
	if err := vpc.ValidatePortRange(config.EgressConfig.ListenerPort); err != nil {
		return err
	}

	// verify that the egress vip is a valid CIDR
	var egressVIPConfig = config.EgressConfig.VIP
	if egressVIPConfig == nil {
		return fmt.Errorf("missing required parameter: EgressConfig VIP")
	}
	if egressVIPConfig.IPv4CIDR == "" {
		return fmt.Errorf("missing required parameter: EgressConfig IPv4 CIDR Address")
	}

	trimCIDR := strings.TrimSpace(egressVIPConfig.IPv4CIDR)
	if proto, valid := vpc.IsValidCIDR(trimCIDR); !valid || proto != iptables.ProtocolIPv4 {
		return fmt.Errorf("invalid parameter: EgressConfig IPv4 CIDR Address")
	}

	if config.EnableIPv6 {
		trimCIDR := strings.TrimSpace(egressVIPConfig.IPv6CIDR)
		if trimCIDR == "" {
			return fmt.Errorf("missing EgressConfig IPv6 CIDR Address")
		}
		if proto, valid := vpc.IsValidCIDR(trimCIDR); !valid || proto != iptables.ProtocolIPv6 {
			return fmt.Errorf("invalid parameter: EgressConfig IPv6 CIDR Address")
		}
	}
	return nil
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
