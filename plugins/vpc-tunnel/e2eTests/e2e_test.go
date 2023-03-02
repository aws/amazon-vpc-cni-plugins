// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
	"strconv"
	"testing"
	"time"

	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-tunnel/plugin"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

const (
	containerID        = "container_1"
	nsName             = "testNS"
	vni                = "CB0CF5"
	geneveIPv4Address  = "169.254.0.1/31"
	gatewayIPv4Address = "169.254.0.0"
	destinationIP      = "10.0.2.129"
	trunkName          = "eth1"
	destinationPort    = 6081
	primary            = "true"
	netConfJsonFmt     = `
{
	"type": "vpc-tunnel",
	"cniVersion":"0.3.0",
	"destinationIPAddress": "%s",
	"vni": "%s",
	"ipAddresses": ["%s"],
	"gatewayIPAddress": "%s",
	"primary": %s,
	"interfaceType": "geneve",
	"destinationPort": "%d"
}
`
)

var ifName = fmt.Sprintf(plugin.GeneveLinkNameFormat, vni, destinationPort)

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
	pluginPath, err := invoke.FindInPath("vpc-tunnel", []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, "Unable to find vpc-tunnel plugin in path")

	// Create a directory for storing test logs.
	testLogDir, err := os.MkdirTemp("", "vpc-tunnel-cni-e2eTests-test-")
	err = os.Chmod(testLogDir, 0755)
	require.NoError(t, err, "Unable to create directory for storing test logs")

	// Configure the env var to use the test logs directory.
	os.Setenv("VPC_CNI_LOG_FILE", fmt.Sprintf("%s/vpc-tunnel.log", testLogDir))
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

	netConfJson := fmt.Sprintf(netConfJsonFmt, destinationIP, vni, geneveIPv4Address, gatewayIPv4Address,
		primary, destinationPort)
	netConf := []byte(netConfJson)

	// Execute the "ADD" command for the plugin.
	execInvokeArgs.Command = "ADD"
	err = invoke.ExecPluginWithoutResult(
		context.Background(),
		pluginPath,
		netConf,
		execInvokeArgs,
		nil)
	require.NoError(t, err, "Unable to execute ADD command for vpc-tunnel cni plugin")

	targetNS.Run(func() error {
		validateAfterAddFunc(t)
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
	require.NoError(t, err, "Unable to execute DEL command for vpc-tunnel cni plugin")

	targetNS.Run(func() error {
		validateAfterDelFunc(t)
		return nil
	})
}

func validateAfterAdd(t *testing.T) {
	// When the geneve link is just brought up and brought down by another test, there will be some
	// delay before the same geneve link is up again, even though the plugin brings it up.
	time.Sleep(2 * time.Second)

	// Check that geneve link exists and is up.
	geneve, err := netlink.LinkByName(ifName)
	require.NoError(t, err)

	assert.Equal(t, "geneve", geneve.Type())

	geneveAttrs := geneve.Attrs()
	assert.NotNil(t, geneveAttrs)
	assert.Equal(t, "unknown", geneveAttrs.OperState.String())

	// Check IP addresses.
	validateIPAddress(t, geneve, netlink.FAMILY_V4, geneveIPv4Address)

	// Check default routes.
	validateDefaultRoute(t, geneve, netlink.FAMILY_V4, gatewayIPv4Address)

	// Check arp rules
	validateArpEntry(t, geneve, netlink.FAMILY_V4)
}

func validateAfterDel(t *testing.T) {
	// Check geneve link is deleted.
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

func validateArpEntry(t *testing.T, link netlink.Link, family int) {
	neighs, err := netlink.NeighList(link.Attrs().Index, family)
	require.NoError(t, err)
	require.NotEmpty(t, neighs)
}
