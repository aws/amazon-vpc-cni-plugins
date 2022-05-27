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
	"net"

	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"

	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/coreos/go-iptables/iptables"
)

// NetConfig defines the network configuration for the ecs-serviceconnect CNI plugin.
type NetConfig struct {
	cniTypes.NetConf
	IngressListenerToInterceptPortMap map[int]int
	EgressPort                        int
	EgressIPv4CIDR                    string
	EgressIPv6CIDR                    string
	IPProtocols                       []iptables.Protocol
}

// netConfigJSON defines the network configuration JSON file format for the ecs-serviceconnect CNI plugin.
type netConfigJSON struct {
	/**
	 * ingressConfig (optional) specifies the netfilter rules to be set for incoming requests.
	 * egressConfig (optional) specifies the netfilter rules to be set for outgoing requests.
	 * enableIPv4 (optional) specifies whether to set the rules in IPV4 table. Note that this
	 * cannot be inferred from egressConfig since it is optional. Default value is false.
	 * Note that this needs to be specified for both dual-stack and V4-only traffic.
	 * enableIPv6 (optional) specifies whether to set the rules in IPV6 table. Default value is false.
	 * Note that this needs to be specified for both dual-stack and V6-only traffic.
	 */
	cniTypes.NetConf
	IngressConfig []ingressConfigJSONEntry `json:"ingressConfig"`
	EgressConfig  *egressConfigJSON        `json:"egressConfig"`
	EnableIPv4    bool                     `json:"enableIPv4"`
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

	// Parse the configuration.
	return parseConfig(&config)
}

// parseConfig parses the given network configuration and returns the in-memory model and any error in parsing.
func parseConfig(config *netConfigJSON) (*NetConfig, error) {
	if len(config.IngressConfig) == 0 && config.EgressConfig == nil {
		return nil, fmt.Errorf("either IngressConfig or EgressConfig must be present")
	}
	if !config.EnableIPv4 && !config.EnableIPv6 {
		return nil, fmt.Errorf("both V4 and V6 cannot be disabled")
	}
	ingressListenerToInterceptPortMap, err := parseIngressConfig(config)
	if err != nil {
		return nil, err
	}
	egressPort, egressIPv4CIDR, egressIPv6CIDR, err := parseEgressConfig(config)
	if err != nil {
		return nil, err
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

// parseIngressConfig parses Ingress Configuration and returns a map of listener port to intercept port.
func parseIngressConfig(config *netConfigJSON) (map[int]int, error) {
	ingressListenerToInterceptPortMap := make(map[int]int)
	for _, s := range config.IngressConfig {
		// verify that the ports are valid
		if err := vpc.ValidatePortRange(s.ListenerPort); err != nil {
			return nil, err
		}
		if s.InterceptPort != 0 {
			if err := vpc.ValidatePortRange(s.InterceptPort); err != nil {
				return nil, err
			}
			ingressListenerToInterceptPortMap[s.ListenerPort] = s.InterceptPort
		}
	}
	return ingressListenerToInterceptPortMap, nil
}

// parseEgressConfig parses the egress configuration and returns the egress listener port and the V4 & V6 CIDR range.
func parseEgressConfig(config *netConfigJSON) (int, string, string, error) {
	if config.EgressConfig == nil {
		return 0, "", "", nil
	}

	// Verify that the port is valid.
	if err := vpc.ValidatePortRange(config.EgressConfig.ListenerPort); err != nil {
		return 0, "", "", err
	}

	// Verify that the egress vip is a valid CIDR.
	egressVIPConfig := config.EgressConfig.VIP
	if egressVIPConfig == nil {
		return 0, "", "", fmt.Errorf("missing required parameter: EgressConfig VIP")
	}

	// Verify that atleast one of the egress CIDRs are set.
	if egressVIPConfig.IPv4CIDR == "" && egressVIPConfig.IPv6CIDR == "" {
		return 0, "", "", fmt.Errorf("missing required parameter: EgressConfig VIP CIDR")
	}

	// Verify that the CIDR is set for the respective IP version.
	if (config.EnableIPv4 && egressVIPConfig.IPv4CIDR == "") ||
		(config.EnableIPv6 && egressVIPConfig.IPv6CIDR == "") {
		return 0, "", "", fmt.Errorf("missing required parameter: EgressConfig VIP CIDR")
	}

	// Verify the value of IPV4 CIDR.
	if egressVIPConfig.IPv4CIDR != "" {
		if ip, _, err := net.ParseCIDR(egressVIPConfig.IPv4CIDR); err != nil || ip.To4() == nil {
			return 0, "", "", fmt.Errorf("invalid parameter: EgressConfig IPv4 CIDR Address")
		}
	}
	// Verify the value of IPV6 CIDR.
	if egressVIPConfig.IPv6CIDR != "" {
		if ip, _, err := net.ParseCIDR(egressVIPConfig.IPv6CIDR); err != nil || ip.To16() == nil {
			return 0, "", "", fmt.Errorf("invalid parameter: EgressConfig IPv6 CIDR Address")
		}
	}
	return config.EgressConfig.ListenerPort, config.EgressConfig.VIP.IPv4CIDR, config.EgressConfig.VIP.IPv6CIDR, nil
}

// getIPProtocols returns the IP protocols that need to be handled for the config.
func getIPProtocols(config *netConfigJSON) []iptables.Protocol {
	var ipProtos []iptables.Protocol
	if config.EnableIPv4 {
		ipProtos = append(ipProtos, iptables.ProtocolIPv4)
	}
	if config.EnableIPv6 {
		ipProtos = append(ipProtos, iptables.ProtocolIPv6)
	}
	return ipProtos
}
