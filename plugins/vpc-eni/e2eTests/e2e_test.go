//go:build e2e_test
// +build e2e_test

// Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package e2e

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"testing"

	"github.com/aws/amazon-vpc-cni-plugins/network/eni"
	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

// TODO: ENI Name is optional so add a test in which ENI Name is not provided
const (
	ifName        = "eni-test-eth0"
	containerID   = "contain-er"
	netConfFormat = `
{
    "type":"vpc-eni",
    "cniVersion":"1.0.0",
    "name":"eni-test",
    "eniName":"%s",
    "eniMACAddress":"%s",
    "eniIPAddresses":["%s", "%s"],
    "gatewayIPAddresses":["%s"],
    "useExistingNetwork":false,
    "blockInstanceMetadata":true,
    "opState":true
}`
	imdsEndpoint      = "169.254.169.254/32"
	eniIPAddress1     = "166.0.0.2/16"
	eniIPAddress2     = "167.0.0.2/16"
	eniGatewayAddress = "166.0.0.1"
)

func init() {
	// This is to ensure that all the namespace operations are performed for
	// a single thread
	runtime.LockOSThread()
}

type config struct {
	region         string
	subnet         string
	index          int64
	instanceID     string
	securityGroups []string
	vpc            string
}

// Tests Add and Del commands for vpc-eni plugin.
func TestAddDel(t *testing.T) {
	testCases := []struct {
		name                  string
		shouldPopulateENIName bool
		testENIName           string
	}{
		{"without eni name", false, "vpc-eni-test-1"},
		{"with eni name", true, "vpc-eni-test-2"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			eniPluginPath := ensureCNIPluginExists(t)

			testLogDir := createTestLogsDir(t)
			defer cleanupLogsIfNeeded(t, testLogDir)

			logFileEnvVar := setLogFileEnvVar(t, testLogDir)
			defer os.Unsetenv(logFileEnvVar)

			logLevelEnvVar := setLogLevelEnvVar()
			defer os.Unsetenv(logLevelEnvVar)

			targetNS := createTestTargetNS(t)
			defer targetNS.Close()

			// testENIName := fmt.Sprintf("%s-%d", "vpc-eni-test", rand.Intn(100))
			testENILink, err := netlink.LinkByName(tc.testENIName)
			require.NoError(t, err, "test ENI not found: "+tc.testENIName)
			testENIMACAddress := testENILink.Attrs().HardwareAddr

			// Construct args to invoke the CNI plugin with
			execInvokeArgs := &invoke.Args{
				Command:     "ADD",
				ContainerID: containerID,
				NetNS:       targetNS.Path(),
				IfName:      ifName,
				Path:        os.Getenv("CNI_PATH"),
			}
			netConfENIName := ""
			if tc.shouldPopulateENIName {
				netConfENIName = tc.testENIName
			}
			netConf := []byte(fmt.Sprintf(netConfFormat,
				netConfENIName, testENIMACAddress, eniIPAddress1, eniIPAddress2, eniGatewayAddress))
			t.Logf("Using config: %s", string(netConf))

			// Invoke ADD command on the plugin
			err = invoke.ExecPluginWithoutResult(context.Background(), eniPluginPath,
				netConf, execInvokeArgs, nil)
			require.NoError(t, err)

			// Validate the target NetNS
			targetNS.Do(func(ns.NetNS) error {
				requireLinksCount(t, 2) // expecting lo and ENI
				requireInterface(t, ifName, testENIMACAddress)
				requireIPAddresses(t, testENIMACAddress, []string{eniIPAddress1, eniIPAddress2})
				validateTargetNSRoutes(t, eniGatewayAddress)
				return nil
			})

			// Invoke DEL command on the plugin
			execInvokeArgs.Command = "DEL"
			err = invoke.ExecPluginWithoutResult(context.Background(), eniPluginPath,
				netConf, execInvokeArgs, nil)
			require.NoError(t, err, "Unable to execute DEL command for vpc-eni plugin")

			// Validate the target NetNS
			targetNS.Do(func(ns.NetNS) error {
				// Validate that the ENI is no longer in the target netns
				_, err := netlink.LinkByName(ifName)
				assert.EqualError(t, err, "Link not found")
				return nil
			})
		})
	}
}

// validateTargetNSRoutes validates routes in the target network namespace
func validateTargetNSRoutes(t *testing.T, expectedGatewayAddr string) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	require.NoError(t, err, "Unable to list routes")

	var imdsRouteFound, gatewayRouteFound bool
	for _, route := range routes {
		if route.Gw == nil && route.Dst.String() == imdsEndpoint {
			imdsRouteFound = true
		}
		if route.Gw != nil && route.Dst == nil {
			gatewayRouteFound = true
			assert.Equal(t, route.Gw.String(), expectedGatewayAddr)
		}
	}

	assert.True(t, imdsRouteFound, "Blocking route for instance metadata not found ")
	assert.True(t, gatewayRouteFound, "Gateway route not found")
}

// Ensures that vpc-eni plugin executable is available.
func ensureCNIPluginExists(t *testing.T) string {
	eniPluginPath, err := invoke.FindInPath("vpc-eni", []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, "Unable to find eni plugin in path")
	return eniPluginPath
}

// Creates a temporary directory for storing plugin logs.
func createTestLogsDir(t *testing.T) string {
	testLogDir, err := os.MkdirTemp("", "vpc-eni-cni-e2eTests-test-")
	err = os.Chmod(testLogDir, 0755)
	require.NoError(t, err, "Unable to create directory for storing test logs")
	return testLogDir
}

// Sets VPC_CNI_LOG_FILE environment variable to make plugin logs go to the
// provided test log directory.
func setLogFileEnvVar(t *testing.T, testLogDir string) string {
	varName := "VPC_CNI_LOG_FILE"
	os.Setenv(varName, fmt.Sprintf("%s/vpc-eni.log", testLogDir))
	t.Logf("Using %s for test logs", testLogDir)
	return varName
}

// Sets VPC_CNI_LOG_LEVEL environment variable to debug so that debug logs are generated
// by the plugin.
func setLogLevelEnvVar() string {
	varName := "VPC_CNI_LOG_LEVEL"
	os.Setenv(varName, "debug")
	return varName
}

// Cleans up log files generated by the test unless ECS_PRESERVE_E2E_TEST_LOGS environment
// variable is set to true.
func cleanupLogsIfNeeded(t *testing.T, testLogDir string) {
	preserve, err := strconv.ParseBool(getEnvOrDefault("ECS_PRESERVE_E2E_TEST_LOGS", "false"))
	assert.NoError(t, err, "Unable to parse ECS_PRESERVE_E2E_TEST_LOGS env var")
	if !t.Failed() && !preserve {
		t.Logf("Removing test logs at %s", testLogDir)
		os.RemoveAll(testLogDir)
	} else {
		t.Logf("Preserving test logs at %s", testLogDir)
	}
}

// Creates a target netns for testing
func createTestTargetNS(t *testing.T) ns.NetNS {
	targetNS, err := testutils.NewNS()
	require.NoError(t, err, "Unable to create a target netns for testing")
	return targetNS
}

// getEnvOrDefault gets the value of an env var. It returns the fallback value
// if the env var is not set
func getEnvOrDefault(name string, fallback string) string {
	val := os.Getenv(name)
	if val == "" {
		return fallback
	}
	return val
}

// Requires that a given number of links are found in this netns.
func requireLinksCount(t *testing.T, count int) {
	links, err := netlink.LinkList()
	require.NoError(t, err, "Unable to list devices in target network namespace")
	assert.Len(t, links, count, "Incorrect number of devices discovered in taget network namespace")
}

// Requires that an interface of a provided Name and MAC Address exists in this netns.
func requireInterface(t *testing.T, ifName string, macAddress net.HardwareAddr) {
	eniLink, err := netlink.LinkByName(ifName)
	require.NoError(t, err, "ENI not found in target netns: "+ifName)
	require.Equal(t, macAddress.String(), eniLink.Attrs().HardwareAddr.String())
}

// Requires that IP addresses of the interface with the provided MAC Address match the
// provided expected IP addresses.
func requireIPAddresses(t *testing.T, macAddress net.HardwareAddr, expectedAddrs []string) {
	interfaces, err := net.Interfaces()
	require.NoError(t, err, "Failed to get interfaces")
	iface := eni.GetInterfaceByMACAddress(macAddress, interfaces)
	addrs, err := iface.Addrs()
	require.NoError(t, err, "Failed to get addresses of interface: "+iface.Name)
	actualAddrs := []string{}
	for _, ip := range addrs {
		actualAddrs = append(actualAddrs, ip.String())
	}
	for _, ip := range expectedAddrs {
		assert.Contains(t, actualAddrs, ip)
	}
}
