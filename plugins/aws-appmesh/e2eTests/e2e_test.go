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

//go:build e2e_test
// +build e2e_test

package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/aws-appmesh/config"
	cniInvoke "github.com/containernetworking/cni/pkg/invoke"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypesCurrent "github.com/containernetworking/cni/pkg/types/100"
	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	cniSpecVersion     = "1.0.0"
	ingressChain       = "APPMESH_INGRESS"
	egressChain        = "APPMESH_EGRESS"
	uid                = "1337"
	gid                = "133"
	appPorts           = "5000,5001"
	proxyEgressPort    = "8080"
	proxyIngressPort   = "8000"
	egressIgnoredPorts = "80,81"
	// we allow at most 15 ports for now
	maximumPort                = 15
	egressIgnoredMultiports    = "80,81,82,83,84,85,86,87,88,89,90,91,92,93,94"
	egressIgnoredIP            = "192.168.100.0/22,163.107.163.107,2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	egressIgnoredIPv4Addresses = "192.168.100.0/22,163.107.163.107"
	egressIgnoredIPv6Addresses = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
	containerID                = "contain-er"
	ifName                     = "test"
	nsName                     = "awsAppmeshTestNS"
)

type testMeta struct {
	name     string
	errorMsg string
}

var (
	pluginPath string
)

// TestValid tests when network configuration is valid.
func TestValid(t *testing.T) {
	initTest(t)

	for _, meta := range []testMeta{
		{
			name: "valid_ingress_egress",
		},
		{
			name: "valid_without_ingress",
		},
		{
			name: "valid_with_multiports",
		},
	} {
		t.Run(meta.name, func(t *testing.T) {
			testValid(t, meta)
		})
	}
}

// TestInvalid tests when network configuration is invalid.
func TestInvalid(t *testing.T) {
	initTest(t)
	for _, meta := range []testMeta{
		{
			name:     "invalid_without_app_ports",
			errorMsg: "missing parameter appPorts (required if proxyIngressPort is provided)",
		},
		{
			name:     "invalid_without_proxy_ingress_port",
			errorMsg: "missing parameter proxyIngressPort (required if appPorts are provided)",
		},
		{
			name:     "invalid_without_proxy_egress_port",
			errorMsg: "missing required parameter proxyEgressPort",
		},
	} {
		t.Run(meta.name, func(t *testing.T) {
			testInvalid(t, meta)
		})
	}
}

// initTest sets up the environment for cni executable.
func initTest(t *testing.T) {
	// Ensure that the eni plugin exists.
	var err error

	pluginPath, err = cniInvoke.FindInPath("aws-appmesh", []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, "Unable to find aws-appmesh plugin in path")

	// Create a directory for storing test logs.
	testLogDir, err := os.MkdirTemp("", "aws-appmesh-cni-e2eTests-test-")
	err = os.Chmod(testLogDir, 0755)
	require.NoError(t, err, "Unable to create directory for storing test logs")

	// Configure the env var to use the test logs directory.
	os.Setenv("VPC_CNI_LOG_FILE", fmt.Sprintf("%s/aws-appmesh.log", testLogDir))
	t.Logf("Using %s for test logs", testLogDir)
	defer os.Unsetenv("VPC_CNI_LOG_FILE")

	// Handle deletion of test logs at the end of the test execution if specified.
	ok, err := strconv.ParseBool(getEnvOrDefault("ECS_PRESERVE_E2E_TEST_LOGS", "false"))
	assert.NoError(t, err, "Unable to parse ECS_PRESERVE_E2E_TEST_LOGS env var")
	defer func(preserve bool) {
		if !t.Failed() && !preserve {
			os.RemoveAll(testLogDir)
		}
	}(ok)
}

// testInvalid verifies that cni ADD command returns error.
func testInvalid(t *testing.T, meta testMeta) {
	netConfData := loadTestData(t, meta.name)
	ctx := context.Background()

	// Create a network namespace to mimic the container's network namespace.
	targetNS, err := netns.NewNetNS(nsName)
	require.NoError(t, err,
		"Unable to create the network namespace that represents the network namespace of the container")
	defer targetNS.Close()

	// Construct args to invoke the CNI plugin with.
	execInvokeArgs := &cniInvoke.Args{
		ContainerID: containerID,
		NetNS:       targetNS.GetPath(),
		IfName:      ifName,
		Path:        os.Getenv("CNI_PATH"),
	}

	// Execute the "ADD" command for the plugin.
	execInvokeArgs.Command = "ADD"
	err = cniInvoke.ExecPluginWithoutResult(
		ctx,
		pluginPath,
		netConfData,
		execInvokeArgs,
		nil)
	assert.EqualError(t, err, meta.errorMsg)
}

// testValid verifies that cni ADD and DEL command succeed.
func testValid(t *testing.T, meta testMeta) {
	netConfData := loadTestData(t, meta.name)
	ctx := context.Background()
	// Create a network namespace to mimic the container's network namespace.
	targetNS, err := netns.NewNetNS(nsName)
	require.NoError(t, err,
		"Unable to create the network namespace that represents the network namespace of the container")
	defer targetNS.Close()

	// Construct args to invoke the CNI plugin with.
	execInvokeArgs := &cniInvoke.Args{
		ContainerID: containerID,
		NetNS:       targetNS.GetPath(),
		IfName:      ifName,
		Path:        os.Getenv("CNI_PATH"),
	}

	// Execute the "ADD" command for the plugin.
	execInvokeArgs.Command = "ADD"
	res, err := cniInvoke.ExecPluginWithResult(
		ctx,
		pluginPath,
		netConfData,
		execInvokeArgs,
		nil)
	require.NoError(t, err, "Unable to execute ADD command for aws-appmesh cni plugin")

	netConf, err := config.New(&cniSkel.CmdArgs{
		StdinData: netConfData,
	})
	require.NoError(t, err, "Unable to create NetConfig object for provided netConf string")

	// Test that the plugin passed previous CNI result unmodified.
	resCurr, err := res.GetAsVersion(cniSpecVersion)
	assert.NoError(t, err, "Unable to parse result")
	result := resCurr.(*cniTypesCurrent.Result)
	assert.Equal(t, "10.1.2.3/16", result.IPs[0].Address.String())

	targetNS.Run(func() error {
		// Validate IP rules successfully added.
		validateIPRules(t, netConf)
		return nil
	})

	// Execute the "DEL" command for the plugin.
	execInvokeArgs.Command = "DEL"
	err = cniInvoke.ExecPluginWithoutResult(
		ctx,
		pluginPath,
		netConfData,
		execInvokeArgs,
		nil)
	require.NoError(t, err, "Unable to execute DEL command for aws-appmesh cni plugin")

	targetNS.Run(func() error {
		// Validate IP rules successfully deleted.
		validateIPRulesDeleted(t)
		return nil
	})

	// Execute the "DEL" again to make sure DEL is idompotent
	err = cniInvoke.ExecPluginWithoutResult(
		ctx,
		pluginPath,
		netConfData,
		execInvokeArgs,
		nil)
	require.NoError(t, err, "Unable to execute DEL command again")
}

// loadTestData loads test cases in json form.
func loadTestData(t *testing.T, name string) []byte {
	path := filepath.Join("testdata", name+".json")
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes
}

// validateIPRules validates IP rules created in the target network namespace.
func validateIPRules(t *testing.T, netConf *config.NetConfig) {

	protocols := []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6}

	for _, proto := range protocols {
		iptable, err := iptables.NewWithProtocol(proto)
		require.NoError(t, err, "Unable to initialize iptable")

		validateIngressIptableRules(t, iptable, netConf)
		validateEgressIptableRules(t, proto, iptable, netConf)
	}
}

// validateIngressIptableRules validates that ingress iptable rules are setup correctly.
func validateIngressIptableRules(t *testing.T, iptable *iptables.IPTables, netConf *config.NetConfig) {
	exist, _ := iptable.Exists("nat", ingressChain, "-p", "tcp", "-m", "multiport", "--dports",
		appPorts, "-j", "REDIRECT", "--to-port", proxyIngressPort)
	if netConf.ProxyIngressPort == "" {
		require.False(t, exist, "Found unexpected rules to redirect app ports to proxy")
	} else {
		require.True(t, exist, "Failed to set rules to redirect app ports to proxy")
	}

	exist, _ = iptable.Exists("nat", "PREROUTING", "-p", "tcp", "-m", "addrtype", "!",
		"--src-type", "LOCAL", "-j", ingressChain)
	if netConf.ProxyIngressPort == "" {
		require.False(t, exist, "Found unexpected rule to jump from PREROUTING to ingress chain")
	} else {
		require.True(t, exist, "Failed to set rule to jump from PREROUTING to ingress chain")
	}
}

// validateEgressIptableRules validates that egress iptable rules are setup correctly.
func validateEgressIptableRules(t *testing.T, proto iptables.Protocol, iptable *iptables.IPTables, netConf *config.NetConfig) {
	var exist bool
	var err error

	exist, err = iptable.Exists("nat", egressChain, "-m", "owner", "--uid-owner", uid, "-j", "RETURN")
	require.NoError(t, err, "Unable to check for ignoredUID")
	require.True(t, exist, "Failed to set ignoredUID:"+uid)

	exist, err = iptable.Exists("nat", egressChain, "-m", "owner", "--gid-owner", gid, "-j", "RETURN")
	require.NoError(t, err, "Unable to check for ignoredGID")
	require.True(t, exist, "Failed to set ignoredGID:"+gid)

	// test if multiports more than maximum port number is ignored correctly
	if len(netConf.EgressIgnoredPorts) >= maximumPort {
		exist, err = iptable.Exists("nat", egressChain, "-p", "tcp", "-m", "multiport", "--dports",
			egressIgnoredMultiports, "-j", "RETURN")
	} else {
		exist, err = iptable.Exists("nat", egressChain, "-p", "tcp", "-m", "multiport", "--dports",
			egressIgnoredPorts, "-j", "RETURN")
	}

	require.NoError(t, err, "Unable to check for egressIgnoredPorts")
	if len(netConf.EgressIgnoredPorts) == 0 {
		require.False(t, exist, "Found unexpected rule for egressIgnoredPorts")
	} else {
		require.True(t, exist, "Failed to set egressIgnoredPorts")
	}

	if proto == iptables.ProtocolIPv4 {
		exist, _ = iptable.Exists("nat", egressChain, "-p", "tcp", "-d", egressIgnoredIPv4Addresses,
			"-j", "RETURN")
	} else {
		exist, _ = iptable.Exists("nat", egressChain, "-p", "tcp", "-d", egressIgnoredIPv6Addresses,
			"-j", "RETURN")
	}

	if len(netConf.EgressIgnoredIPv4s) == 0 && len(netConf.EgressIgnoredIPv6s) == 0 {
		require.False(t, exist, "Found unexpected rule for egressIgnoredIPs")
	} else {
		require.True(t, exist, "Failed to set egressIgnoredIPs")
	}

	exist, _ = iptable.Exists("nat", egressChain, "-p", "tcp", "-j", "REDIRECT", "--to",
		proxyEgressPort)
	require.True(t, exist, "Failed to set rule to redirect traffic to proxyEgressPort")

	exist, _ = iptable.Exists("nat", "OUTPUT", "-p", "tcp", "-m", "addrtype", "!",
		"--dst-type", "LOCAL", "-j", egressChain)
	require.True(t, exist, "Failed to set rule to jump from OUTPUT to egress chain")
}

// validateIPRulesDeleted validates IP rules deleted in the target network namespace.
func validateIPRulesDeleted(t *testing.T) {
	protocols := []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6}

	for _, proto := range protocols {
		iptable, err := iptables.NewWithProtocol(proto)
		require.NoError(t, err, "Unable to initialize iptable")

		chains, err := iptable.ListChains("nat")
		require.NoError(t, err, "Unable to list 'nat' chains")

		validateIngressIptableRulesDeleted(t, iptable, chains)
		validateEgressIptableRulesDeleted(t, iptable, chains)
	}
}

// validateIngressIptableRulesDeleted validates ingress IP rules deleted in the target network namespace.
func validateIngressIptableRulesDeleted(t *testing.T, iptable *iptables.IPTables, chains []string) {
	exist, _ := iptable.Exists("nat", ingressChain, "-p", "tcp", "-m", "multiport", "--dports",
		appPorts, "-j", "REDIRECT", "--to-port", proxyIngressPort)
	require.False(t, exist, "Failed to delete rules to redirect app ports to proxy")

	exist, _ = iptable.Exists("nat", "PREROUTING", "-p", "tcp", "-m", "addrtype", "!",
		"--src-type", "LOCAL", "-j", ingressChain)
	require.False(t, exist, "Failed to delete rules to jump from PREROUTING to ingress chain")

	exist = contains(chains, ingressChain)
	require.False(t, exist, "Failed to delete ingress chain")
}

// validateEgressIptableRulesDeleted validates egress IP rules deleted in the target network namespace.
func validateEgressIptableRulesDeleted(t *testing.T, iptable *iptables.IPTables, chains []string) {
	exist := contains(chains, egressChain)
	require.False(t, exist, "Failed to delete egress chain")
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
