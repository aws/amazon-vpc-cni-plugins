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
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"
	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

const (
	testENIName1  = "vpc-eni-test-1" // expected to exist on the host
	testENIName2  = "vpc-eni-test-2" // expected to exist on the host
	testENIName3  = "vpc-eni-test-3" // expected to exist on the host
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
    "blockInstanceMetadata":%s,
    "opState":true
}`
	imdsEndpointIPv4  = "169.254.169.254/32"
	imdsEndpointIPv6  = "fd00:ec2::254/128"
	eniIPAddress1     = "166.0.0.2/16"
	eniIPAddress2     = "167.0.0.2/16"
	eniGatewayAddress = "166.0.0.1"
)

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
		testENIName           string
		shouldPopulateENIName bool
		shouldBlockIMDS       bool
	}{
		{"without eni name", testENIName1, false, true},
		{"with eni name", testENIName2, true, true},
		{"allow imds", testENIName3, false, false},
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

			testENI := createTestInterface(t, tc.testENIName)
			defer deleteTestInterface(t, testENI.Attrs().HardwareAddr)

			testENILink, err := netlink.LinkByName(tc.testENIName)
			require.NoError(t, err, "test ENI not found: "+tc.testENIName)
			testENIMACAddress := testENILink.Attrs().HardwareAddr

			// Construct args to invoke the CNI plugin with
			execInvokeArgs := &invoke.Args{
				Command:     "ADD",
				ContainerID: containerID,
				NetNS:       targetNS.GetPath(),
				IfName:      ifName,
				Path:        os.Getenv("CNI_PATH"),
			}
			netConfENIName := ""
			if tc.shouldPopulateENIName {
				netConfENIName = tc.testENIName
			}
			blockInstanceMetadata := "false"
			if tc.shouldBlockIMDS {
				blockInstanceMetadata = "true"
			}
			netConf := []byte(fmt.Sprintf(netConfFormat,
				netConfENIName, testENIMACAddress, eniIPAddress1, eniIPAddress2,
				eniGatewayAddress, blockInstanceMetadata))
			t.Logf("Using config: %s", string(netConf))

			// Invoke ADD command on the plugin
			err = invoke.ExecPluginWithoutResult(context.Background(), eniPluginPath,
				netConf, execInvokeArgs, nil)
			require.NoError(t, err)

			// Validate the target NetNS
			targetNS.Run(func() error {
				requireLinksCount(t, 2) // expecting lo and ENI
				requireInterface(t, ifName, testENIMACAddress)
				requireIPAddresses(t, testENIMACAddress, []string{eniIPAddress1, eniIPAddress2})
				assertGatewayRoute(t, eniGatewayAddress)
				assertIMDSV4(t, tc.shouldBlockIMDS)
				assertIMDSV6(t, tc.shouldBlockIMDS)
				return nil
			})

			// Invoke DEL command on the plugin
			execInvokeArgs.Command = "DEL"
			err = invoke.ExecPluginWithoutResult(context.Background(), eniPluginPath,
				netConf, execInvokeArgs, nil)
			require.NoError(t, err, "Unable to execute DEL command for vpc-eni plugin")

			// Validate the target NetNS
			targetNS.Run(func() error {
				// Validate that the ENI is no longer in the target netns
				_, err := netlink.LinkByName(ifName)
				assert.EqualError(t, err, "Link not found")
				return nil
			})
		})
	}
}

// Asserts that a gateway route exists and matces expected gateway address.
func assertGatewayRoute(t *testing.T, expectedGatewayAddr string) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	require.NoError(t, err, "Unable to list routes")
	var gatewayRoute netlink.Route
	for _, route := range routes {
		if route.Gw != nil && route.Dst == nil {
			gatewayRoute = route
		}
	}
	assert.Equal(t, gatewayRoute.Gw.String(), expectedGatewayAddr)
}

// Assertions for IMDS via IPv4
func assertIMDSV4(t *testing.T, shouldBeBlocked bool) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	require.NoError(t, err, "Unable to list routes")
	var imdsRoute *netlink.Route
	for _, route := range routes {
		if route.Dst.String() == imdsEndpointIPv4 {
			imdsRoute = &route
			break
		}
	}
	if shouldBeBlocked {
		require.NotNil(t, imdsRoute, "IMDS v4 block route not found")
		assert.Equal(t, syscall.RTN_BLACKHOLE, imdsRoute.Type, "IMDS IPv4 route is not blocked")
	} else {
		assert.Nil(t, imdsRoute, "No route is expected for IMDS if it shouldn't be blocked")
	}
}

// Assertions for IMDS via IPv6
func assertIMDSV6(t *testing.T, shouldBeBlocked bool) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V6)
	require.NoError(t, err, "Unable to list routes")
	var imdsRoute *netlink.Route
	for _, route := range routes {
		if route.Dst.String() == imdsEndpointIPv6 {
			imdsRoute = &route
			break
		}
	}
	if shouldBeBlocked {
		require.NotNil(t, imdsRoute, "IMDS v6 block route not found")
		assert.Equal(t, syscall.RTN_BLACKHOLE, imdsRoute.Type, "IMDS IPv6 route is not blocked")
	} else {
		assert.Nil(t, imdsRoute, "No route is expected for IMDS if it shouldn't be blocked")
	}
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
func createTestTargetNS(t *testing.T) netns.NetNS {
	targetNS, err := netns.NewNetNS(fmt.Sprintf("eni-test-ns-%d", time.Now().UnixMilli()))
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
	iface := getInterfaceByMACAddress(macAddress, interfaces)
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

// getInterfaceByMACAddress returns the interface with the specified MAC address.
func getInterfaceByMACAddress(macAddress net.HardwareAddr, interfaces []net.Interface) *net.Interface {
	var chosenInterface *net.Interface

	// If there are multiple matches, pick the one with the shortest name.
	for i := 0; i < len(interfaces); i++ {
		iface := &interfaces[i]
		if vpc.CompareMACAddress(iface.HardwareAddr, macAddress) {
			if chosenInterface == nil || len(chosenInterface.Name) > len(iface.Name) {
				chosenInterface = iface
			}
		}
	}

	return chosenInterface
}

// Creates a test (dummy) network interface
func createTestInterface(t *testing.T, linkName string) netlink.Link {
	t.Log("Creating test ENI", linkName)

	macAddr, err := generateMACAddress()
	require.NoError(t, err, "Failed to generate MAC Address for test ENI")

	la := netlink.NewLinkAttrs()
	la.Name = linkName
	la.HardwareAddr = macAddr
	err = netlink.LinkAdd(&netlink.Dummy{LinkAttrs: la})
	require.NoError(t, err, "Failed to create test ENI")

	link, err := netlink.LinkByName(linkName)
	require.NoError(t, err, "Failed to find test ENI by name after creation")
	t.Log("Created test ENI", link)

	return link
}

// generateMACAddress generates a random locally-administrated MAC address.
func generateMACAddress() (net.HardwareAddr, error) {
	buf := make([]byte, 6)
	var mac net.HardwareAddr

	_, err := rand.Read(buf)
	if err != nil {
		return mac, err
	}

	// Set locally administered addresses bit and reset multicast bit
	buf[0] = (buf[0] | 0x02) & 0xfe
	mac = append(mac, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])
	return mac, nil
}

// Deletes test ENI
func deleteTestInterface(t *testing.T, macAddress net.HardwareAddr) {
	// Find the interface by MAC address
	t.Log("Looking up test ENI with mac address", macAddress)
	interfaces, err := net.Interfaces()
	require.NoError(t, err, "Failed to get interfaces")
	iface := getInterfaceByMACAddress(macAddress, interfaces)
	require.NotNil(t, iface, fmt.Sprintf(
		"An interface with mac address %s was not found: %v", macAddress, interfaces))
	t.Log("Found test ENI for deletion", iface.Name)

	// Delete the interface
	link, err := netlink.LinkByName(iface.Name)
	require.NoError(t, err, "Failed to find link to delete", iface.Name)
	err = netlink.LinkDel(link)
	require.NoError(t, err, "Failed to delete test ENI", iface.Name)
	t.Log("Deleted test ENI", link.Attrs().Name)
}
