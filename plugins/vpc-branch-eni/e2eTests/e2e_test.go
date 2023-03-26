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
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"testing"
	"text/template"
	"time"

	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"
	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

type NetconfFieldsMap struct {
	Trunk              string
	BranchVlanID       uint16
	BranchMACAddress   string
	BranchIPv4Address  string
	BranchIPv6Address  string
	GatewayIPv4Address string
	GatewayIPv6Address string
	BlockIMDS          bool
}

func netconfFields() NetconfFieldsMap {
	return NetconfFieldsMap{
		Trunk:              "eth1",
		BranchVlanID:       101,
		BranchMACAddress:   "02:e1:48:75:86:a4",
		BranchIPv4Address:  "172.31.19.6/20",
		BranchIPv6Address:  "2600:1f13:4d9:e602:6aea:cdb1:2b2b:8d62/64",
		GatewayIPv4Address: "172.31.16.1",
		GatewayIPv6Address: "2600:1f13:4d9:e602::1234",
		BlockIMDS:          false,
	}
}

func netconfFieldsBlockIMDS() NetconfFieldsMap {
	return NetconfFieldsMap{
		Trunk:              "eth2",
		BranchVlanID:       102,
		BranchMACAddress:   "02:e1:48:75:88:a4",
		BranchIPv4Address:  "172.32.19.6/20",
		BranchIPv6Address:  "2600:1f13:4d9:e604:6aea:cdb1:2b2b:8d62/64",
		GatewayIPv4Address: "172.32.16.1",
		GatewayIPv6Address: "2600:1f13:4d9:e604::1234",
		BlockIMDS:          true,
	}
}

const (
	containerID = "container_1"

	// template
	netConfJsonFmt = `
{
	"type": "vpc-branch-eni",
	"name": "vpc-branch-eni-test-network",
	"cniVersion":"0.3.0",
	"trunkName": "{{.Trunk}}",
	"branchVlanID": "{{.BranchVlanID}}",
	"branchMACAddress": "{{.BranchMACAddress}}",
	"ipAddresses": ["{{.BranchIPv4Address}}","{{.BranchIPv6Address}}"],
	"gatewayIPAddresses": ["{{.GatewayIPv4Address}}","{{.GatewayIPv6Address}}"],
	"blockInstanceMetadata": {{.BlockIMDS}},
	"interfaceType": "vlan"
}
`

	// constants for TestAddDel
	ifName = "testIf"
	nsName = "vpcBranchEniTestNS"

	// constants for TestAddDelBlockIMDS
	ifNameBlockIMDS = "blockImdsTestIf"
	nsNameBlockIMDS = "vpcBranchEniBlockImdsTestNS"
)

func TestAddDelBlockIMDS(t *testing.T) {
	testAddDel(
		t,
		netconfFieldsBlockIMDS(),
		nsNameBlockIMDS,
		ifNameBlockIMDS,
		validateAfterAddBlockIMDS,
		validateAfterDel,
	)
}

func TestAddDel(t *testing.T) {
	var err error

	// Bring down the trunk interface so that we can ensure the plugin is not assuming the trunk interface
	// is already brought up.
	la := netlink.NewLinkAttrs()
	la.Name = netconfFields().Trunk
	link := &netlink.Dummy{LinkAttrs: la}
	err = netlink.LinkSetDown(link)
	require.NoError(t, err)

	testAddDel(
		t,
		netconfFields(),
		nsName,
		ifName,
		validateAfterAdd,
		validateAfterDel,
	)
}

func testAddDel(
	t *testing.T,
	inputNetconfFields NetconfFieldsMap,
	netNsName string,
	interfaceName string,
	validateAfterAddFunc,
	validateAfterDelFunc func(*testing.T, string, NetconfFieldsMap),
) {
	// Ensure that the cni plugin exists.
	pluginPath, err := invoke.FindInPath("vpc-branch-eni", []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, "Unable to find vpc-branch-eni plugin in path")

	// Create a directory for storing test logs.
	testLogDir, err := os.MkdirTemp("", "vpc-branch-eni-cni-e2eTests-test-")
	err = os.Chmod(testLogDir, 0755)
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
	targetNS, err := netns.NewNetNS(netNsName)
	fmt.Println("Created target namespace")
	require.NoError(t, err,
		"Unable to create the network namespace that represents the network namespace of the container")
	defer targetNS.Close()

	// Construct args to invoke the CNI plugin with.
	execInvokeArgs := &invoke.Args{
		ContainerID: containerID,
		NetNS:       targetNS.GetPath(),
		IfName:      interfaceName,
		Path:        os.Getenv("CNI_PATH"),
	}

	var netConfBytes bytes.Buffer
	netConfJsonTpl := template.Must(template.New("testAddDel").Parse(netConfJsonFmt))
	tplExecErr := netConfJsonTpl.Execute(&netConfBytes, inputNetconfFields)
	require.NoErrorf(t, tplExecErr, "Unable to fill in the netconf template using %+v", inputNetconfFields)
	netConf := netConfBytes.Bytes()

	// Execute the "ADD" command for the plugin.
	execInvokeArgs.Command = "ADD"
	err = invoke.ExecPluginWithoutResult(
		context.Background(),
		pluginPath,
		netConf,
		execInvokeArgs,
		nil)
	require.NoError(t, err, "Unable to execute ADD command for vpc-branch-eni cni plugin")

	targetNS.Run(func() error {
		validateAfterAddFunc(t, interfaceName, inputNetconfFields)
		return nil
	})

	// Execute the "DEL" command for the plugin.
	execInvokeArgs.Command = "DEL"
	err = invoke.ExecPluginWithoutResult(
		context.Background(),
		pluginPath,
		netConf,
		execInvokeArgs,
		nil)
	require.NoError(t, err, "Unable to execute DEL command for vpc-branch-eni cni plugin")

	targetNS.Run(func() error {
		validateAfterDelFunc(t, interfaceName, inputNetconfFields)
		return nil
	})
}

func validateAfterAddBlockIMDS(
	t *testing.T,
	interfaceName string,
	expectedFields NetconfFieldsMap,
) {
	validateAfterAdd(t, interfaceName, expectedFields)

	// Check that there's no route to go to IMDS endpoint.
	for _, ep := range vpc.InstanceMetadataEndpoints {
		imdsIP := net.ParseIP(ep)
		_, err := netlink.RouteGet(imdsIP)
		assert.Error(t, err)
	}
}

func validateAfterAdd(
	t *testing.T,
	interfaceName string,
	expectedFields NetconfFieldsMap,
) {
	// Give some time for the link to come up, we just initialized it, if this time is
	// too short, the link status will be `unknown` instead of `up` even though
	// everything is actually set up properly.
	time.Sleep(2 * time.Second)

	// Check that branch link exists and is up.
	branch, err := netlink.LinkByName(interfaceName)
	require.NoError(t, err)

	assert.Equal(t, "vlan", branch.Type())

	branchAttrs := branch.Attrs()
	assert.NotNil(t, branch.Attrs())
	assert.Equal(t, "up", branchAttrs.OperState.String())
	assert.Equal(t, expectedFields.BranchMACAddress, branchAttrs.HardwareAddr.String())

	// Check IP addresses.
	validateIPAddress(t, branch, netlink.FAMILY_V4, expectedFields.BranchIPv4Address)
	validateIPAddress(t, branch, netlink.FAMILY_V6, expectedFields.BranchIPv6Address)

	// Check default routes.
	validateDefaultRoute(t, branch, netlink.FAMILY_V4, expectedFields.GatewayIPv4Address)
	validateDefaultRoute(t, branch, netlink.FAMILY_V6, expectedFields.GatewayIPv6Address)
}

func validateAfterDel(
	t *testing.T,
	interfaceName string,
	expectedFields NetconfFieldsMap,
) {
	// Check branch link is deleted.
	_, err := netlink.LinkByName(interfaceName)
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
