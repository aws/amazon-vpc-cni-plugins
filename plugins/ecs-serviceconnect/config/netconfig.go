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

// RedirectMode defines the type of redirection of traffic to be used.
type RedirectMode string

const (
	NAT    RedirectMode = "nat"
	TPROXY              = "tproxy"
)

// NetConfig defines the network configuration for the ecs-serviceconnect CNI plugin.
type NetConfig struct {
	cniTypes.NetConf
	IngressListenerToInterceptPortMap map[int]int
	EgressPort                        int
	EgressRedirectMode                RedirectMode
	EgressRedirectIPv4Addr            string
	EgressRedirectIPv6Addr            string
	EgressIPv4CIDR                    string
	EgressIPv6CIDR                    string
	IPProtocols                       []iptables.Protocol
}

// netConfigJSON defines the network configuration JSON file format for the
// ecs-serviceconnect CNI plugin.
type netConfigJSON struct {
	/**
	 * ingressConfig (optional) specifies the netfilter rules to be set for incoming requests.
	 * egressConfig (optional) specifies the netfilter rules to be set for outgoing requests.
	 * enableIPv4 (optional) specifies whether to set the rules in IPV4 table. Note that this
	 * cannot be inferred from egressConfig since it is optional. Default value is false.
	 * Note that this needs to be set to true for both dual-stack and V4-only traffic.
	 * enableIPv6 (optional) specifies whether to set the rules in IPV6 table.
	 * Default value is false. Note that this needs to be set to true for both dual-stack
	 * and V6-only traffic.
	 */
	cniTypes.NetConf
	IngressConfig []ingressConfigJSONEntry `json:"ingressConfig"`
	EgressConfig  *egressConfigJSON        `json:"egressConfig"`
	EnableIPv4    bool                     `json:"enableIPv4"`
	EnableIPv6    bool                     `json:"enableIPv6"`
}

// ingressConfigJSONEntry defines the ingress network config in JSON format for the
// ecs-serviceconnect CNI plugin.
type ingressConfigJSONEntry struct {
	ListenerPort  int `json:"listenerPort"`
	InterceptPort int `json:"interceptPort,omitempty"`
}

// egressConfigJSON defines the egress network config in JSON format for the
// ecs-serviceconnect CNI plugin.
type egressConfigJSON struct {
	ListenerPort int             `json:"listenerPort"`
	RedirectIP   *redirectIPJson `json:"redirectIP"`
	RedirectMode string          `json:"redirectMode"`
	VIP          *vipConfigJSON  `json:"vip"`
}

// redirectIPJson defines the IP to be redirected in JSON format for the
// ecs-serviceconnect CNI plugin.
type redirectIPJson struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

// vipConfigJSON defines the EgressVIP network config in JSON format for the
// ecs-serviceconnect CNI plugin.
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

// parseConfig parses the given network configuration and returns the in-memory model
// and any error in parsing.
func parseConfig(config *netConfigJSON) (*NetConfig, error) {
	if len(config.IngressConfig) == 0 && config.EgressConfig == nil {
		return nil, fmt.Errorf("either IngressConfig or EgressConfig must be present")
	}
	if !config.EnableIPv4 && !config.EnableIPv6 {
		return nil, fmt.Errorf("both V4 and V6 cannot be disabled")
	}

	// Populate NetConfig.
	netConfig := NetConfig{
		NetConf:     config.NetConf,
		IPProtocols: getIPProtocols(config),
	}

	err := parseIngressConfig(config, &netConfig)
	if err != nil {
		return nil, err
	}

	err = parseEgressConfig(config, &netConfig)
	if err != nil {
		return nil, err
	}

	return &netConfig, nil
}

// parseIngressConfig parses Ingress Configuration and populates ingress port map
// in the given NetConfig.
func parseIngressConfig(config *netConfigJSON, netConfig *NetConfig) error {
	ingressListenerToInterceptPortMap := make(map[int]int)
	for _, s := range config.IngressConfig {
		// verify that the ports are valid
		if err := vpc.ValidatePortRange(s.ListenerPort); err != nil {
			return err
		}
		if s.InterceptPort != 0 {
			if err := vpc.ValidatePortRange(s.InterceptPort); err != nil {
				return err
			}
			ingressListenerToInterceptPortMap[s.ListenerPort] = s.InterceptPort
		}
	}
	netConfig.IngressListenerToInterceptPortMap = ingressListenerToInterceptPortMap
	return nil
}

// validateRedirectMode validates the redirection mode.
func validateRedirectMode(redirectMode RedirectMode, egressConfig *egressConfigJSON) error {
	switch redirectMode {
	case NAT:
		if egressConfig.ListenerPort == 0 {
			return fmt.Errorf("missing required parameter: Egress ListenerPort")
		} else {
			return nil
		}
	case TPROXY:
		return nil
	}
	return fmt.Errorf("invalid parameter: Egress RedirectMode")
}

// parseEgressConfig parses the egress configuration and populates the egress parameters
// in the given netConfig.
func parseEgressConfig(config *netConfigJSON, netConfig *NetConfig) error {
	if config.EgressConfig == nil {
		return nil
	}

	if (config.EgressConfig.ListenerPort == 0 && config.EgressConfig.RedirectIP == nil) ||
		(config.EgressConfig.ListenerPort != 0 && config.EgressConfig.RedirectIP != nil) {
		return fmt.Errorf("exactly one of ListenerPort and RedirectIP must be " +
			"specified in Egress")
	}
	redirectMode := RedirectMode(config.EgressConfig.RedirectMode)
	if err := validateRedirectMode(redirectMode, config.EgressConfig); err != nil {
		return err
	}

	if config.EgressConfig.ListenerPort != 0 {
		// Verify that the port is valid.
		if err := vpc.ValidatePortRange(config.EgressConfig.ListenerPort); err != nil {
			return err
		}
	}
	redirectIP := config.EgressConfig.RedirectIP
	if redirectIP != nil {
		if (config.EnableIPv4 && redirectIP.IPv4 == "") ||
			(config.EnableIPv6 && redirectIP.IPv6 == "") {
			return fmt.Errorf("missing required parameter: EgressConfig Redirect IP")
		}
		if redirectIP.IPv4 != "" {
			if ip := net.ParseIP(redirectIP.IPv4); ip == nil {
				return fmt.Errorf("invalid parameter: EgressConfig RedirectIP")
			}
			netConfig.EgressRedirectIPv4Addr = redirectIP.IPv4
		}
		if redirectIP.IPv6 != "" {
			if ip := net.ParseIP(redirectIP.IPv6); ip == nil {
				return fmt.Errorf("invalid parameter: EgressConfig RedirectIP")
			}
			netConfig.EgressRedirectIPv6Addr = redirectIP.IPv6
		}
	}

	// Verify that the egress vip is a valid CIDR.
	egressVIPConfig := config.EgressConfig.VIP
	if egressVIPConfig == nil {
		return fmt.Errorf("missing required parameter: EgressConfig VIP")
	}

	// Verify that atleast one of the egress CIDRs are set.
	if egressVIPConfig.IPv4CIDR == "" && egressVIPConfig.IPv6CIDR == "" {
		return fmt.Errorf("missing required parameter: EgressConfig VIP CIDR")
	}

	// Verify that the CIDR is set for the respective IP version.
	if (config.EnableIPv4 && egressVIPConfig.IPv4CIDR == "") ||
		(config.EnableIPv6 && egressVIPConfig.IPv6CIDR == "") {
		return fmt.Errorf("missing required parameter: EgressConfig VIP CIDR")
	}

	// Verify the value of IPV4 CIDR.
	if egressVIPConfig.IPv4CIDR != "" {
		if ip, _, err := net.ParseCIDR(egressVIPConfig.IPv4CIDR); err != nil || ip.To4() == nil {
			return fmt.Errorf("invalid parameter: EgressConfig IPv4 CIDR Address")
		}
	}
	// Verify the value of IPV6 CIDR.
	if egressVIPConfig.IPv6CIDR != "" {
		if ip, _, err := net.ParseCIDR(egressVIPConfig.IPv6CIDR); err != nil || ip.To16() == nil {
			return fmt.Errorf("invalid parameter: EgressConfig IPv6 CIDR Address")
		}
	}

	// Populate Egress config.
	netConfig.EgressRedirectMode = redirectMode
	netConfig.EgressPort = config.EgressConfig.ListenerPort
	netConfig.EgressIPv4CIDR = config.EgressConfig.VIP.IPv4CIDR
	netConfig.EgressIPv6CIDR = config.EgressConfig.VIP.IPv6CIDR

	return nil
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
