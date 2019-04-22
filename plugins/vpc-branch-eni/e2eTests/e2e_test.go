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
	"golang.org/x/sys/unix"
)

const (
	containerID            = "container_1"
	ifName                 = "testIf"
	nsName                 = "testNS"
	trunkMACAddress        = "02:71:ca:81:41:1e"
	branchVlanID           = "101"
	branchMACAddress       = "02:e1:48:75:86:a4"
	branchIPAddress        = "172.31.19.6/20"
	branchGatewayIPAddress = "172.31.16.1"
	netConfJsonFmt         = `
{
	"type": "vpc-branch-eni",
	"cniVersion":"0.3.0",
	"trunkMACAddress": "%s",
	"branchVlanID": "%s",
	"branchMACAddress": "%s",
	"branchIPAddress": "%s",
	"branchGatewayIPAddress": "%s",
	"interfaceType": "vlan"
}
`
	netConfJsonFmtBlockIMDS = `
{
	"type": "vpc-branch-eni",
	"cniVersion":"0.3.0",
	"trunkMACAddress": "%s",
	"branchVlanID": "%s",
	"branchMACAddress": "%s",
	"branchIPAddress": "%s",
	"branchGatewayIPAddress": "%s",
	"interfaceType": "vlan",
	"blockInstanceMetadata": true
}
`
)

func TestAddDelBlockIMDS(t *testing.T) {
	testAddDel(t, netConfJsonFmtBlockIMDS, validateAfterAddBlockIMDS, validateAfterDel)
}

func TestAddDel(t *testing.T) {
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

	netConfJson := fmt.Sprintf(netConfJsonFmt, trunkMACAddress, branchVlanID, branchMACAddress,
		branchIPAddress, branchGatewayIPAddress)
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

	// Check default route.
	routes, err := netlink.RouteList(branch, unix.NETLINK_ROUTE)
	assert.Equal(t, branchGatewayIPAddress, routes[0].Gw.String())
	assert.Equal(t, branchAttrs.Index, routes[0].LinkIndex)
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
