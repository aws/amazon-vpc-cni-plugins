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

//go:build unit_test

package config

import (
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/stretchr/testify/assert"
)

type config struct {
	netConfig string
}

var (
	validConfigs = []config{
		{
			netConfig: `{"ignoredUID":"1337", "proxyIngressPort":"8080", "proxyEgressPort":"8000", "appPorts":["1223","2334"], "egressIgnoredPorts":["80","81"], "egressIgnoredIPs":["216.3.128.12","216.3.128.12/24","2001:0db8:85a3:0000:0000:8a2e:0370:7334"]}`,
		},
		{
			netConfig: `{"ignoredUID":"1337", "proxyIngressPort":"8080", "proxyEgressPort":"8000", "appPorts":["1223","2334"], "egressIgnoredPorts":["80"], "egressIgnoredIPs":["216.3.128.12/24","2001:0db8:85a3:0000:0000:8a2e:0370:7334/32"]}`,
		},
		{
			netConfig: `{"ignoredUID":"1337", "proxyIngressPort":"8080", "proxyEgressPort":"8000", "appPorts":["1223","2334"], "egressIgnoredIPs":["216.3.128.12"]}`,
		},
		{
			netConfig: `{"ignoredGID":"1337", "proxyIngressPort":"8080", "proxyEgressPort":"8000", "appPorts":["1223"]}`,
		},
		{
			netConfig: `{"ignoredGID":"1337", "proxyIngressPort":"8080", "proxyEgressPort":"8000", "appPorts":[""]}`,
		},
		{
			// no ingress traffic, e.g. batch job.
			netConfig: `{"ignoredGID":"1337", "proxyEgressPort":"8000"}`,
		},
	}

	invalidConfigs = []config{
		{
			netConfig: `{"ignoredUID":"1337"}`,
		},
		{
			netConfig: `{"ignoredUID":"1337", "proxyIngressPort":"ab80", "proxyEgressPort":"8000", "appPorts":["1223","2334"]}`,
		},
		{
			netConfig: `{"ignoredUID":"1337", "proxyIngressPort":"8080", "proxyEgressPort":"8000", "appPorts":["1223","2334"], "egressIgnoredPorts":["80"], "egressIgnoredIPs":["12a.22b.128.12","2001:0db8:85a3:0000:0000:8a2e:0370:7334"]}`,
		},
		{
			netConfig: `{"ignoredGID":"1337", "proxyIngressPort":"8080", "proxyEgressPort":"8000"}`,
		},
		{
			netConfig: `{"ignoredGID":"1337", "proxyEgressPort":"8000", "appPorts":["1223"]}`,
		},
	}
)

func TestValidConfigs(t *testing.T) {
	for _, config := range validConfigs {
		args := &skel.CmdArgs{
			StdinData: []byte(config.netConfig),
		}
		_, err := New(args)

		assert.NoError(t, err)
	}
}

func TestInvalidConfigs(t *testing.T) {
	// Test all invalid configs.
	for _, config := range invalidConfigs {
		args := &skel.CmdArgs{
			StdinData: []byte(config.netConfig),
		}
		_, err := New(args)
		assert.Error(t, err)
	}
}

func TestNew(t *testing.T) {
	args := &skel.CmdArgs{
		StdinData: []byte(validConfigs[0].netConfig),
	}
	config, err := New(args)
	assert.NoError(t, err)
	assert.Equal(t, "1337", config.IgnoredUID)
	assert.Equal(t, "", config.IgnoredGID)
	assert.Equal(t, "8080", config.ProxyIngressPort)
	assert.Equal(t, "8000", config.ProxyEgressPort)
	assert.Equal(t, []string{"1223", "2334"}, config.AppPorts)
	assert.Equal(t, []string{"80", "81"}, config.EgressIgnoredPorts)
	assert.Equal(t, "216.3.128.12,216.3.128.12/24", config.EgressIgnoredIPv4s)
	assert.Equal(t, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", config.EgressIgnoredIPv6s)

}

func TestSeparateIPsSuccess(t *testing.T) {
	ips := []string{"216.3.128.12", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "216.3.128.12/24", "2001:0db8:85a3:0000:0000:8a2e:0370:7334/32"}
	ipv4s, ipv6s, err := separateIPs(ips)
	assert.Nil(t, err)
	assert.Equal(t, "216.3.128.12,216.3.128.12/24", ipv4s)
	assert.Equal(t, "2001:0db8:85a3:0000:0000:8a2e:0370:7334,2001:0db8:85a3:0000:0000:8a2e:0370:7334/32", ipv6s)
}

func TestSeparateIPsFailure(t *testing.T) {
	ipSlices := make([][]string, 2)
	ipSlices[0] = []string{"12a.222.333/444", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"}
	ipSlices[1] = []string{"123.222.333.444", "2001:0db8:85a3:0000:0000:8a2e:0370/7334"}
	for _, ips := range ipSlices {
		_, _, err := separateIPs(ips)
		assert.Error(t, err)
	}
}

func TestIsValidPortWithValidPort(t *testing.T) {
	ports := []string{"1337", "311"}
	for _, port := range ports {
		result := isValidPort(port)
		assert.NoError(t, result)
	}
}

func TestIsValidPortWithInvalidPort(t *testing.T) {
	type Port struct {
		port           string
		expectedResult string
	}

	ports := []Port{
		{port: "a", expectedResult: "invalid port [a] specified"},
		{port: "1*ab", expectedResult: "invalid port [1*ab] specified"},
		{port: " 1", expectedResult: "invalid port [ 1] specified"},
		{port: "-1", expectedResult: "invalid port [-1] specified"},
		{port: "1.1", expectedResult: "invalid port [1.1] specified"},
	}
	for _, port := range ports {
		result := isValidPort(port.port)
		assert.Equal(t, port.expectedResult, result.Error())
	}

}

func TestIsValidIPAddressOrCIDR(t *testing.T) {
	type IPAddr struct {
		ip            string
		expectedProto string
		expectedValid bool
	}
	ips := []IPAddr{
		{ip: "216.3.128.12", expectedProto: ipv4Proto, expectedValid: true},
		{ip: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", expectedProto: ipv6Proto, expectedValid: true},
		{ip: "2001:0db8::0000:0000:8a2e:0370:7334", expectedProto: ipv6Proto, expectedValid: true},
		{ip: "216.3.128.12/24", expectedProto: ipv4Proto, expectedValid: true},
		{ip: "2001:0db8:85a3:0000:0000:8a2e:0370:7334/32", expectedProto: ipv6Proto, expectedValid: true},
		{ip: "a", expectedProto: "", expectedValid: false},
		{ip: "1*ab", expectedProto: "", expectedValid: false},
		{ip: "123.222.333.444/24", expectedProto: "", expectedValid: false},
		{ip: "123.222..444", expectedProto: "", expectedValid: false},
		{ip: "123.222/333.444", expectedProto: "", expectedValid: false},
	}
	for _, ip := range ips {
		proto, valid := isValidIPAddressOrCIDR(ip.ip)
		assert.Equal(t, ip.expectedProto, proto)
		assert.Equal(t, ip.expectedValid, valid)
	}
}
