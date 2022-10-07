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

//go:build !integration_test && !e2e_test
// +build !integration_test,!e2e_test

package config

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/assert"
)

type testConfig struct {
	filePath           string
	ingressMap         map[int]int
	egressPort         int
	egressRedirectIP   string
	egressRedirectMode RedirectMode
	egressIpv4Vip      string
	egressIpv6Vip      string
	protos             []iptables.Protocol
}

// loadTestData loads test cases in json form.
func loadTestData(t *testing.T, name string) []byte {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(wd), "testdata", name+".json")
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes
}

func TestValidConfigs(t *testing.T) {
	for _, config := range []testConfig{
		{
			filePath:      "valid_empty_ingress",
			ingressMap:    map[int]int{},
			egressPort:    30002,
			egressIpv4Vip: "127.255.0.0/16",
			protos:        []iptables.Protocol{iptables.ProtocolIPv4},
		},
		{
			filePath:      "valid_ingress_with_port_intercept_1",
			ingressMap:    map[int]int{30000: 8080, 30001: 8090},
			egressPort:    30002,
			egressIpv4Vip: "127.255.0.0/16",
			protos:        []iptables.Protocol{iptables.ProtocolIPv4},
		},
		{
			filePath:      "valid_ingress_with_port_intercept_2",
			ingressMap:    map[int]int{30000: 8080},
			egressPort:    30002,
			egressIpv4Vip: "127.255.0.0/16",
			egressIpv6Vip: "2002::1234:abcd:ffff:c0a8:101/64",
			protos:        []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6},
		},
		{
			filePath:      "valid_ingress_without_port_intercept",
			ingressMap:    map[int]int{},
			egressPort:    30002,
			egressIpv4Vip: "127.255.0.0/16",
			egressIpv6Vip: "2002::1234:abcd:ffff:c0a8:101/64",
			protos:        []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6},
		},
		{
			filePath:   "valid_without_egress",
			ingressMap: map[int]int{},
			egressPort: 0,
			protos:     []iptables.Protocol{iptables.ProtocolIPv4},
		},
		{
			filePath:      "valid_without_ingress",
			ingressMap:    map[int]int{},
			egressPort:    30002,
			egressIpv4Vip: "127.255.0.0/16",
			protos:        []iptables.Protocol{iptables.ProtocolIPv4},
		},
	} {
		args := &skel.CmdArgs{
			StdinData: []byte(loadTestData(t, config.filePath)),
		}
		netConfig, err := New(args)

		assert.NoError(t, err)
		assert.Equal(t, config.ingressMap, netConfig.IngressListenerToInterceptPortMap)
		assert.Equal(t, config.egressPort, netConfig.EgressPort)
		assert.Equal(t, config.egressIpv4Vip, netConfig.EgressIPv4CIDR)
		assert.Equal(t, config.egressIpv6Vip, netConfig.EgressIPv6CIDR)
	}
}

func TestInvalidConfigs(t *testing.T) {
	// Test all invalid configs.
	for _, config := range []string{
		"invalid_egress_ipv4_cidr_1", "invalid_egress_ipv4_cidr_2",
		"invalid_egress_ipv6_cidr_1", "invalid_egress_ipv6_cidr_2",
		"invalid_egress_listener_port", "invalid_egress_redirect_ip_1",
		"invalid_egress_redirect_ip_2", "invalid_egress_redirect_ip_3",
		"invalid_empty_egress", "invalid_empty_egress_vip",
		"invalid_ingress_intercept_port", "invalid_ingress_listener_port",
		"invalid_missing_egress_listener_port", "invalid_missing_egress_vip",
		"invalid_missing_ingress_egress", "invalid_missing_ingress_listener_port",
		"invalid_missing_ip", "invalid_missing_redirect_mode", "invalid_redirect_mode",
		"invalid_v6_missing_egress_vip",
	} {
		args := &skel.CmdArgs{
			StdinData: []byte(loadTestData(t, config)),
		}
		_, err := New(args)
		assert.Error(t, err)
	}
}
