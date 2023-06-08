// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesCurrent "github.com/containernetworking/cni/pkg/types/100"
	cniVersion "github.com/containernetworking/cni/pkg/version"
)

// NetConfig defines the network configuration for the aws-appmesh cni plugin.
type NetConfig struct {
	cniTypes.NetConf
	PrevResult         *cniTypesCurrent.Result
	IgnoredUID         string
	IgnoredGID         string
	ProxyIngressPort   string
	ProxyEgressPort    string
	AppPorts           []string
	EgressIgnoredPorts []string
	EgressIgnoredIPv4s string
	EgressIgnoredIPv6s string
	EnableIPv6         bool
}

// netConfigJSON defines the network configuration JSON file format for the aws-appmesh cni plugin.
type netConfigJSON struct {
	cniTypes.NetConf
	PrevResult map[string]interface{} `json:"prevResult,omitempty"`

	IgnoredUID         string   `json:"ignoredUID"`
	IgnoredGID         string   `json:"ignoredGID"`
	ProxyIngressPort   string   `json:"proxyIngressPort"`
	ProxyEgressPort    string   `json:"proxyEgressPort"`
	AppPorts           []string `json:"appPorts"`
	EgressIgnoredPorts []string `json:"egressIgnoredPorts"`
	EgressIgnoredIPs   []string `json:"egressIgnoredIPs"`
	EnableIPv6         bool     `json:"enableIPv6"`
}

const (
	splitter  = ","
	ipv4Proto = "IPv4"
	ipv6Proto = "IPv6"
)

// New creates a new NetConfig object by parsing the given CNI arguments.
func New(args *cniSkel.CmdArgs) (*NetConfig, error) {
	// Parse network configuration.
	var config netConfigJSON
	if err := json.Unmarshal(args.StdinData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse network config: %v", err)
	}

	// Validate network configuration.
	if err := validateConfig(&config); err != nil {
		return nil, err
	}

	// Get separate lists of IPv4 address/CIDR block and IPv6 address/CIDR block.
	ipv4s, ipv6s, err := separateIPs(config.EgressIgnoredIPs)
	if err != nil {
		return nil, err
	}

	// Populate NetConfig.
	netConfig := NetConfig{
		NetConf:            config.NetConf,
		IgnoredUID:         config.IgnoredUID,
		IgnoredGID:         config.IgnoredGID,
		ProxyIngressPort:   config.ProxyIngressPort,
		ProxyEgressPort:    config.ProxyEgressPort,
		AppPorts:           config.AppPorts,
		EgressIgnoredIPv4s: ipv4s,
		EgressIgnoredIPv6s: ipv6s,
		EgressIgnoredPorts: config.EgressIgnoredPorts,
		EnableIPv6:         config.EnableIPv6,
	}

	if config.PrevResult != nil {
		// Plugin was called as part of a chain. Parse the previous result to pass forward.
		prevResBytes, err := json.Marshal(config.PrevResult)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize prevResult: %v", err)
		}

		prevRes, err := cniVersion.NewResult(config.CNIVersion, prevResBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse prevResult: %v", err)
		}

		netConfig.PrevResult, err = cniTypesCurrent.NewResultFromResult(prevRes)
		if err != nil {
			return nil, fmt.Errorf("failed to convert result to current version: %v", err)
		}
	} else {
		// Plugin was called stand-alone.
		netConfig.PrevResult = &cniTypesCurrent.Result{}
	}

	// Validation complete. Return the parsed NetConfig object.
	log.Debugf("Created NetConfig: %+v", netConfig)
	return &netConfig, nil
}

// validateConfig validates network configuration.
func validateConfig(config *netConfigJSON) error {
	// Validate if all the required fields are present.
	if config.IgnoredGID == "" && config.IgnoredUID == "" {
		return fmt.Errorf("missing required parameter ignoredGID or ignoredUID")
	}
	if config.ProxyEgressPort == "" {
		return fmt.Errorf("missing required parameter proxyEgressPort")
	}

	// AppPorts and ProxyIngressPort go in pairs,
	// i.e. either both are set or both are not set.
	if config.ProxyIngressPort == "" && len(config.AppPorts) > 0 {
		return fmt.Errorf("missing parameter proxyIngressPort (required if appPorts are provided)")
	}

	if config.ProxyIngressPort != "" && len(config.AppPorts) == 0 {
		return fmt.Errorf("missing parameter appPorts (required if proxyIngressPort is provided)")
	}

	// Validate the format of all fields.
	if err := isValidPort(config.ProxyEgressPort); err != nil {
		return err
	}
	if err := isValidPort(config.ProxyIngressPort); err != nil {
		return err
	}

	// If incoming ports or IP addresses are empty we still treat that as valid and delete that empty element.
	if len(config.AppPorts) == 1 && config.AppPorts[0] == "" {
		config.AppPorts = nil
	}

	for _, port := range config.AppPorts {
		if err := isValidPort(port); err != nil {
			return err
		}
	}

	if len(config.EgressIgnoredPorts) == 1 && config.EgressIgnoredPorts[0] == "" {
		config.EgressIgnoredPorts = nil
	}

	for _, port := range config.EgressIgnoredPorts {
		if err := isValidPort(port); err != nil {
			return err
		}
	}

	if len(config.EgressIgnoredIPs) == 1 && config.EgressIgnoredIPs[0] == "" {
		config.EgressIgnoredIPs = nil
	}
	return nil
}

// separateIPs separate IPv4 addresses/CIDR block and IPv6 addresses/CIDR block
// into two lists.
func separateIPs(ignoredIPs []string) (string, string, error) {
	if len(ignoredIPs) == 0 {
		return "", "", nil
	}

	var ipv4s, ipv6s []string
	for _, ip := range ignoredIPs {
		trimIP := strings.TrimSpace(ip)
		proto, valid := isValidIPAddressOrCIDR(trimIP)
		if !valid {
			return "", "", fmt.Errorf("invalid IP or CIDR block [%s] specified in egressIgnoredIPs", trimIP)
		}

		if proto == ipv4Proto {
			ipv4s = append(ipv4s, trimIP)
		} else {
			ipv6s = append(ipv6s, trimIP)
		}

	}
	return strings.Join(ipv4s, splitter), strings.Join(ipv6s, splitter), nil
}

// isValidPort checks whether the port only has digits.
func isValidPort(port string) error {
	if port == "" {
		return nil
	}

	i, err := strconv.Atoi(port)
	if err == nil && i > 0 {
		return nil
	}

	return fmt.Errorf("invalid port [%s] specified", port)
}

// isValidIPAddressOrCIDR checks whether the input is a valid IP addresses/CIDR block and checks the IP protocol.
func isValidIPAddressOrCIDR(address string) (string, bool) {
	ip := net.ParseIP(address)
	var err error
	if ip == nil {
		// Check whether it is a valid CIDR block.
		ip, _, err = net.ParseCIDR(address)
		if err != nil {
			return "", false
		}
	}

	// There's no To6() method in the `net` package. Instead, just check that
	// it's not a valid `v4` IP.
	if ip.To4() != nil {
		return ipv4Proto, true
	}
	return ipv6Proto, true
}
