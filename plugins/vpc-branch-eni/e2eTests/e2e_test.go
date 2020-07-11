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

// +build e2e_test, vpc_branch_eni

package e2e

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

const (
	containerID        = "container_1"
	ifName             = "testIf"
	nsName             = "testNS"
	trunkName          = "eth1"
	branchVlanID       = "101"
	branchMACAddress   = "02:e1:48:75:86:a4"
	branchIPv4Address  = "172.31.19.6/20"
	branchIPv6Address  = "2600:1f13:4d9:e602:6aea:cdb1:2b2b:8d62/64"
	gatewayIPv4Address = "172.31.16.1"
	gatewayIPv6Address = "2600:1f13:4d9:e602::1234"
	netConfJsonFmt     = `
{
	"type": "vpc-branch-eni",
	"cniVersion":"0.3.0",
	"trunkName": "%s",
	"branchVlanID": "%s",
	"branchMACAddress": "%s",
	"ipAddresses": ["%s","%s"],
	"gatewayIPAddresses": ["%s","%s"],
	"interfaceType": "vlan"
}
`
	netConfJsonFmtBlockIMDS = `
{
	"type": "vpc-branch-eni",
	"cniVersion":"0.3.0",
	"trunkName": "%s",
	"branchVlanID": "%s",
	"branchMACAddress": "%s",
	"ipAddresses": ["%s","%s"],
	"gatewayIPAddresses": ["%s","%s"],
	"interfaceType": "vlan",
	"blockInstanceMetadata": true
}
`
)

func TestAddDelBlockIMDS(t *testing.T) {
	testAddDel(t, netConfJsonFmtBlockIMDS, validateAfterAddBlockIMDS, validateAfterDel)
}

func TestAddDel(t *testing.T) {
	var err error

	// Bring down the trunk interface so that we can ensure the plugin is not assuming the trunk interface
	// is already brought up.
	la := netlink.NewLinkAttrs()
	la.Name = trunkName
	link := &netlink.Dummy{LinkAttrs: la}
	err = netlink.LinkSetDown(link)
	require.NoError(t, err)

	testAddDel(t, netConfJsonFmt, validateAfterAdd, validateAfterDel)
}

func testAddDel(t *testing.T, netConfJsonFmt string, validateAfterAddFunc, validateAfterDelFunc func(*testing.T)) {
	// Ensure that the cni plugin exists.
	pluginPath, err := invoke.FindInPath("vpc-branch-eni", []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, "Unable to find vpc-branch-eni plugin in path")

	// Create a directory for storing test logs.
	testLogDir, err := ioutil.TempDir("", "vpc-branch-eni-cni-e2eTests-test-")
	require.NoError(t, err, "Unable to create directory for storing test logs")

	// Configure the env var to use the test logs directory.
	os.Setenv("VPC_CNI_LOG_FILE", fmt.Sprintf("%s/vpc-branch-eni.log", testLogDir))
	t.Logf("Using %s for test logs", testLogDir)
	defer os.Unsetenv("VPC_CNI_LOG_FILE")

	// Configure logs at debug level.
	os.Setenv("VPC_CNI_LOG_LEVEL", "debug")
	defer os.Unsetenv("VPC_CNI_LOG_LEVEL")

	// Handle deletion of test logs at the end of the test execution if specified.
	ok, err := strconv.ParseBool(getEnvOrDefault("ECS_PRESERVE_E2E_TEST_LOGS", "false"))
	assert.NoError(t, err, "Unable to parse ECS_PRESERVE_E2E_TEST_LOGS env var")
	defer func(preserve bool) {
		if !t.Failed() && !preserve {
			t.Logf("Removing test logs at %s", testLogDir)
			os.RemoveAll(testLogDir)
		} else {
			t.Logf("Preserving test logs at %s", testLogDir)
		}
	}(ok)

	// Create a network namespace to mimic the container's network namespace.
	targetNS, err := netns.NewNetNS(nsName)
	fmt.Println("Created target namespace")
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

	netConfJson := fmt.Sprintf(netConfJsonFmt, trunkName, branchVlanID, branchMACAddress,
		branchIPv4Address, branchIPv6Address, gatewayIPv4Address, gatewayIPv6Address)
	netConf := []byte(netConfJson)

	// Execute the "ADD" command for the plugin.
	execInvokeArgs.Command = "ADD"
	err = invoke.ExecPluginWithoutResult(
		pluginPath,
		netConf,
		execInvokeArgs)
	require.NoError(t, err, "Unable to execute ADD command for vpc-branch-eni cni plugin")

	targetNS.Run(func() error {
		validateAfterAddFunc(t)
		return nil
	})

	// Execute the "DEL" command for the plugin.
	execInvokeArgs.Command = "DEL"
	err = invoke.ExecPluginWithoutResult(
		pluginPath,
		netConf,
		execInvokeArgs)
	require.NoError(t, err, "Unable to execute DEL command for vpc-branch-eni cni plugin")

	targetNS.Run(func() error {
		validateAfterDelFunc(t)
		return nil
	})
}

func validateAfterAdd(t *testing.T) {
	// When the branch link is just brought up and brought down by another test, there will be some
	// delay before the same branch link is up again, even though the plugin brings it up.
	time.Sleep(2 * time.Second)

	// Check that branch link exists and is up.
	branch, err := netlink.LinkByName(ifName)
	require.NoError(t, err)

	assert.Equal(t, "vlan", branch.Type())

	branchAttrs := branch.Attrs()
	assert.NotNil(t, branch.Attrs())
	assert.Equal(t, "up", branchAttrs.OperState.String())
	assert.Equal(t, branchMACAddress, branchAttrs.HardwareAddr.String())

	// Check IP addresses.
	validateIPAddress(t, branch, netlink.FAMILY_V4, branchIPv4Address)
	validateIPAddress(t, branch, netlink.FAMILY_V6, branchIPv6Address)

	// Check default routes.
	validateDefaultRoute(t, branch, netlink.FAMILY_V4, gatewayIPv4Address)
	validateDefaultRoute(t, branch, netlink.FAMILY_V6, gatewayIPv6Address)
}

func validateAfterAddBlockIMDS(t *testing.T) {
	validateAfterAdd(t)

	// Check that there's no route to go to IMDS endpoint.
	imdsIP := net.ParseIP("169.254.169.254")
	_, err := netlink.RouteGet(imdsIP)
	assert.Error(t, err)
}

func validateAfterDel(t *testing.T) {
	// Check branch link is deleted.
	_, err := netlink.LinkByName(ifName)
	assert.Error(t, err)
}

// getEnvOrDefault gets the value of an env var. It returns the default value
// if the env var is not set.
func getEnvOrDefault(name string, defaultValue string) string {
	val := os.Getenv(name)
	if val == "" {
		return defaultValue
	}

	return val
}

// validateIPAddress validates that the link has the given IP address.
func validateIPAddress(t *testing.T, link netlink.Link, family int, ipAddress string) {
	addrs, err := netlink.AddrList(link, family)
	require.NoError(t, err)

	for _, a := range addrs {
		if a.IPNet.String() == ipAddress {
			return
		}
	}

	assert.NoError(t, fmt.Errorf("IP address %s not found", ipAddress))
}

// validateDefaultRoute validates that the link has a default route to the given gateway IP address.
func validateDefaultRoute(t *testing.T, link netlink.Link, family int, gatewayIPAddress string) {
	routes, err := netlink.RouteList(link, family)
	require.NoError(t, err)

	for _, r := range routes {
		if r.Dst == nil && r.Gw != nil {
			assert.Equal(t, gatewayIPAddress, r.Gw.String())
			return
		}
	}

	assert.NoError(t, fmt.Errorf("Default route to gateway %s not found", gatewayIPAddress))
}
