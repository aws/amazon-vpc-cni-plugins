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

// +build e2e_test

package e2e

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"testing"

	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	ingressChain               = "APPMESH_INGRESS"
	egressChain                = "APPMESH_EGRESS"
	uid                        = "1337"
	gid                        = "133"
	appPorts                   = "5000,5001"
	proxyEgressPort            = "8080"
	proxyIngressPort           = "8000"
	egressIgnoredPorts         = "80,81"
	egressIgnoredIP            = "192.168.100.0/22,163.107.163.107,2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	egressIgnoredIPv4Addresses = "192.168.100.0/22,163.107.163.107"
	egressIgnoredIPv6Addresses = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	containerID                = "contain-er"
	ifName                     = "test"
	nsName                     = "testNS"
	netConf                    = `
{
    "type":"aws-appmesh",
    "cniVersion":"0.3.0",
    "ignoredUID":"1337",
    "ignoredGID":"133",
    "proxyEgressPort":"8080",
    "proxyIngressPort":"8000",
    "appPorts":["5000","5001"],
    "egressIgnoredPorts":["80","81"],
    "egressIgnoredIPs":["192.168.100.0/22","163.107.163.107","2001:0db8:85a3:0000:0000:8a2e:0370:7334"]
}`
	netConfMissingParam = `
{
    "type":"aws-appmesh",
    "cniVersion":"0.3.0",
    "ignoredUID":"1337",
    "ignoredGID":"133",
    "proxyEgressPort":"8080",
    "proxyIngressPort":"8000"
}`
)

func TestAddDel(t *testing.T) {
	// Ensure that the cni plugin exists.
	pluginPath, err := invoke.FindInPath("aws-appmesh", []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, "Unable to find aws-appmesh plugin in path")

	// Create a directory for storing test logs.
	testLogDir, err := ioutil.TempDir("", "aws-appmesh-cni-e2eTests-test-")
	require.NoError(t, err, "Unable to create directory for storing test logs")

	// Configure the env var to use the test logs directory.
	os.Setenv("CNI_LOG_FILE", fmt.Sprintf("%s/aws-appmesh.log", testLogDir))
	t.Logf("Using %s for test logs", testLogDir)
	defer os.Unsetenv("CNI_LOG_FILE")

	// Handle deletion of test logs at the end of the test execution if specified.
	ok, err := strconv.ParseBool(getEnvOrDefault("ECS_PRESERVE_E2E_TEST_LOGS", "false"))
	assert.NoError(t, err, "Unable to parse ECS_PRESERVE_E2E_TEST_LOGS env var")
	defer func(preserve bool) {
		if !t.Failed() && !preserve {
			os.RemoveAll(testLogDir)
		}
	}(ok)

	// Create a network namespace to mimic the container's network namespace.
	targetNS, err := netns.NewNetNS(nsName)
	require.NoError(t, err,
		"Unable to create the network namespace that represents the network namespace of the container")
	defer targetNS.Close()

	// Construct args to invoke the CNI plugin with.
	execInvokeArgs := &invoke.Args{
		ContainerID: containerID,
		NetNS:       targetNS.GetPath(),
		IfName:      ifName,
		Path:        os.Getenv("CNI_PATH"),
	}
	netConf := []byte(fmt.Sprintf(netConf))

	// Execute the "ADD" command for the plugin.
	execInvokeArgs.Command = "ADD"
	err = invoke.ExecPluginWithoutResult(
		pluginPath,
		netConf,
		execInvokeArgs)
	require.NoError(t, err, "Unable to execute ADD command for aws-appmesh cni plugin")

	targetNS.Run(func() error {
		// Validate IP rules successfully added.
		validateIPRules(t)
		return nil
	})

	// Execute the "DEL" command for the plugin.
	execInvokeArgs.Command = "DEL"
	err = invoke.ExecPluginWithoutResult(
		pluginPath,
		netConf,
		execInvokeArgs)
	require.NoError(t, err, "Unable to execute DEL command for aws-appmesh cni plugin")

	targetNS.Run(func() error {
		// Validate IP rules successfully deleted.
		validateIPRulesDeleted(t)
		return nil
	})
}

//TestAddReturnError tests when required network configuration is missed, ADD will return error as expected.
func TestAddReturnError(t *testing.T) {
	// Ensure that the eni plugin exists.
	pluginPath, err := invoke.FindInPath("aws-appmesh", []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, "Unable to find aws-appmesh plugin in path")

	// Create a directory for storing test logs.
	testLogDir, err := ioutil.TempDir("", "aws-appmesh-cni-e2eTests-test-")
	require.NoError(t, err, "Unable to create directory for storing test logs")

	// Configure the env var to use the test logs directory.
	os.Setenv("CNI_LOG_FILE", fmt.Sprintf("%s/aws-appmesh.log", testLogDir))
	defer os.Unsetenv("CNI_LOG_FILE")

	// Handle deletion of test logs at the end of the test execution if specified.
	ok, err := strconv.ParseBool(getEnvOrDefault("ECS_PRESERVE_E2E_TEST_LOGS", "false"))
	assert.NoError(t, err, "Unable to parse ECS_PRESERVE_E2E_TEST_LOGS env var")
	defer func(preserve bool) {
		if !t.Failed() && !preserve {
			os.RemoveAll(testLogDir)
		}
	}(ok)

	// Create a network namespace to mimic the container's network namespace.
	targetNS, err := netns.NewNetNS(nsName)
	require.NoError(t, err,
		"Unable to create the network namespace that represents the network namespace of the container")
	defer targetNS.Close()

	// Construct args to invoke the CNI plugin with.
	execInvokeArgs := &invoke.Args{
		ContainerID: containerID,
		NetNS:       targetNS.GetPath(),
		IfName:      ifName,
		Path:        os.Getenv("CNI_PATH"),
	}
	netConf := []byte(fmt.Sprintf(netConfMissingParam))

	// Execute the "ADD" command for the plugin.
	execInvokeArgs.Command = "ADD"
	err = invoke.ExecPluginWithoutResult(
		pluginPath,
		netConf,
		execInvokeArgs)
	assert.EqualError(t, err, "missing required parameter appPorts")
}

// validateIPRules validates IP rules created in the target network namespace.
func validateIPRules(t *testing.T) {

	protocols := []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv4}
	for _, proto := range protocols {
		iptable, err := iptables.NewWithProtocol(proto)
		require.NoError(t, err, "Unable to initialize iptable")

		exist, _ := iptable.Exists("nat", ingressChain, "-p", "tcp", "-m", "multiport", "--dports",
			appPorts, "-j", "REDIRECT", "--to-port", proxyIngressPort)
		require.True(t, exist, "Failed to set rules to redirect app ports to proxy")

		exist, _ = iptable.Exists("nat", "PREROUTING", "-p", "tcp", "-m", "addrtype", "!",
			"--src-type", "LOCAL", "-j", ingressChain)
		require.True(t, exist, "Failed to set rule to jump from PREROUTING to ingress chain")

		exist, _ = iptable.Exists("nat", egressChain, "-m", "owner", "--uid-owner", uid, "-j", "RETURN")
		require.True(t, exist, "Failed to set ignoredUID")

		exist, _ = iptable.Exists("nat", egressChain, "-m", "owner", "--gid-owner", gid, "-j", "RETURN")
		require.True(t, exist, "Failed to set ignoredGID")

		exist, _ = iptable.Exists("nat", egressChain, "-p", "tcp", "-m", "multiport", "--dports",
			egressIgnoredPorts, "-j", "RETURN")
		require.True(t, exist, "Failed to set egressIgnoredPorts")

		if proto == iptables.ProtocolIPv4 {
			exist, _ = iptable.Exists("nat", egressChain, "-p", "tcp", "-d", egressIgnoredIPv4Addresses,
				"-j", "RETURN")
			require.True(t, exist, "Failed to set egressIgnoredIPv4IPs")
		} else {
			exist, _ = iptable.Exists("nat", egressChain, "-p", "tcp", "-d", egressIgnoredIPv6Addresses,
				"-j", "RETURN")
			require.True(t, exist, "Failed to set egressIgnoredIPv6IPs")
		}

		exist, err = iptable.Exists("nat", egressChain, "-p", "tcp", "-j", "REDIRECT", "--to",
			proxyEgressPort)
		require.True(t, exist, "Failed to set rule to redirect traffic to proxyEgressPort")

		exist, err = iptable.Exists("nat", "OUTPUT", "-p", "tcp", "-m", "addrtype", "!",
			"--dst-type", "LOCAL", "-j", egressChain)
		require.True(t, exist, "Failed to set rule to jump from OUTPUT to egress chain")

	}
}

// validateIPRulesDeleted validates IP rules deleted in the target network namespace.
func validateIPRulesDeleted(t *testing.T) {
	protocols := []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv4}
	for _, proto := range protocols {
		iptable, err := iptables.NewWithProtocol(proto)
		require.NoError(t, err, "Unable to initialize iptable")

		exist, _ := iptable.Exists("nat", ingressChain, "-p", "tcp", "-m", "multiport", "--dports",
			appPorts, "-j", "REDIRECT", "--to-port", proxyIngressPort)
		require.False(t, exist, "Failed to delete rules to redirect app ports to proxy")

		exist, _ = iptable.Exists("nat", "PREROUTING", "-p", "tcp", "-m", "addrtype", "!",
			"--src-type", "LOCAL", "-j", ingressChain)
		require.False(t, exist, "Failed to delete rules to jump from PREROUTING to ingress chain")

		chains, err := iptable.ListChains("nat")

		exist = contains(chains, ingressChain)
		require.False(t, exist, "Failed to delete ingress chain")

		exist = contains(chains, egressChain)
		require.False(t, exist, "Failed to delete egress chain")
	}
}

// contains checks whether an element exists in the slices.
func contains(slices []string, ele string) bool {
	for _, e := range slices {
		if e == ele {
			return true
		}
	}
	return false
}

// getEnvOrDefault gets the value of an env var. It returns the fallback value
// if the env var is not set.
func getEnvOrDefault(name string, fallback string) string {
	val := os.Getenv(name)
	if val == "" {
		return fallback
	}

	return val
}
