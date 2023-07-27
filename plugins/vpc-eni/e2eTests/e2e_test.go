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
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	"github.com/pkg/errors"
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
    "eniIPAddresses":["%s"],
    "gatewayIPAddresses":["%s"],
    "useExistingNetwork":false,
    "blockInstanceMetadata":true,
    "opState":true
}`
	imdsEndpoint = "169.254.169.254/32"
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
//
// The Test requires AWS credentials and must be run on an EC2 instance.
//
// The test performs the following steps.
//  1. Request an Elastic Network Interface (ENI) to be created in the EC2 instance's subnet.
//  2. Wait for the ENI to be created and then request for it to be attached to the instance.
//  3. Wait for the ENI to be attached to the instance and then fetch its details.
//  4. Create a new network namespace for testing.
//  5. Invoke vpc-cni plugin's ADD command from the current network namespace
//     to configure the test network namespace with the ENI.
//  6. Verify that two devices (lo and ENI) are present in the test netns.
//  7. Verify that the ENI is UP in the test netns.
//  8. Verify that the expected routes are present in the test netns.
//  9. Invoke vpc-cni plugin's DEL command to tear down the ENI setup from the test netns.
//  10. Verify that the ENI is no longer in the test netns.
func TestAddDel(t *testing.T) {
	testCases := []struct {
		name                  string
		shouldPopulateENIName bool
	}{
		{"without eni name", false},
		{"with eni name", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Ensure that the eni plugin exists
			eniPluginPath, err := invoke.FindInPath("vpc-eni", []string{os.Getenv("CNI_PATH")})
			require.NoError(t, err, "Unable to find eni plugin in path")

			// Ensure that we are able to build a config from instance's metadata
			cfg, err := newConfig()
			require.NoError(t, err, "Unable to get instance config")
			ec2Client := ec2.New(session.Must(session.NewSession()), &aws.Config{
				Region: aws.String(cfg.region),
			})

			// Create an ENI
			eni, err := createENI(ec2Client, cfg)
			require.NoError(t, err, "Unable to create ENI")
			defer deleteENI(ec2Client, eni)
			require.NoError(t, waitUntilNetworkInterfaceAvailable(ec2Client, eni), "ENI didn't transition into 'available'")

			// Attach the ENI to the instance
			attachment, err := attachENI(ec2Client, cfg, eni)
			require.NoError(t, err, "Unable to attach ENI")
			defer detachENI(ec2Client, attachment)
			eniLinkName, err := waitUntilNetworkInterfaceAttached(eni, 5*time.Second)
			require.NoError(t, err, "ENI was not attached to the instance")

			ipv4SubnetGateway, ipv4PrefixLength, err := computeIPv4SubnetGatewayAndPrefixLength(ec2Client, cfg.subnet)
			require.NoError(t, err, "Unable to compute ipv4 subnet gateway for ENI")

			// Create a directory for storing test logs.
			testLogDir, err := os.MkdirTemp("", "vpc-eni-cni-e2eTests-test-")
			err = os.Chmod(testLogDir, 0755)
			require.NoError(t, err, "Unable to create directory for storing test logs")

			// Configure the env var to use the test logs directory.
			os.Setenv("VPC_CNI_LOG_FILE", fmt.Sprintf("%s/vpc-eni.log", testLogDir))
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

			// Use the current network namespace to execute the test in
			testNS, err := ns.GetCurrentNS()
			require.NoError(t, err, "Unable to get test network namespace to run the test in")
			defer testNS.Close()

			// Create a network namespace to mimic the container's network namespace.
			// The ENI will be moved to this namespace
			targetNS, err := testutils.NewNS()
			require.NoError(t, err,
				"Unable to create the network namespace that represents the network namespace of the container")
			defer targetNS.Close()

			// Construct args to invoke the CNI plugin with
			execInvokeArgs := &invoke.Args{
				ContainerID: containerID,
				NetNS:       targetNS.Path(),
				IfName:      ifName,
				Path:        os.Getenv("CNI_PATH"),
			}
			netConfENIName := ""
			if tc.shouldPopulateENIName {
				netConfENIName = eniLinkName
			}
			netConf := []byte(fmt.Sprintf(netConfFormat,
				netConfENIName,
				aws.StringValue(eni.MacAddress),
				aws.StringValue(eni.PrivateIpAddress)+"/"+ipv4PrefixLength,
				ipv4SubnetGateway))
			t.Logf("Using config: %s", string(netConf))

			testNS.Do(func(ns.NetNS) error {
				// Execute the "ADD" command for the plugin
				execInvokeArgs.Command = "ADD"
				err = invoke.ExecPluginWithoutResult(context.Background(), eniPluginPath,
					netConf, execInvokeArgs, nil)
				require.NoError(t, err, "Unable to execute ADD command for vpc-eni plugin")
				return nil
			})

			targetNS.Do(func(ns.NetNS) error {
				// Validate that only 2 devices exist in the target network
				// namespace (lo and eni)
				links, err := netlink.LinkList()
				require.NoError(t, err, "Unable to list devices in target network namespace")
				assert.Len(t, links, 2, "Incorrect number of devices discovered in taget network namespace")
				eniFound := false
				for _, link := range links {
					if link.Attrs().HardwareAddr.String() == aws.StringValue(eni.MacAddress) {
						eniFound = true
						break
					}
				}
				require.True(t, eniFound, "ENI not found in target network namespace")

				// Validate that ENI is UP
				eni, err := netlink.LinkByName(ifName)
				require.NoError(t, err, "ENI interface not found in the target netns")
				require.Equal(t, "up", eni.Attrs().OperState.String(),
					"expected operational state of the ENI insided the container netns to be up")

				// Validate routes in the container netns
				validateTargetNSRoutes(t)
				return nil
			})

			testNS.Do(func(ns.NetNS) error {
				// Execute the "DEL" command for the plugin
				execInvokeArgs.Command = "DEL"
				err = invoke.ExecPluginWithoutResult(context.Background(), eniPluginPath,
					netConf, execInvokeArgs, nil)
				require.NoError(t, err, "Unable to execute DEL command for vpc-eni plugin")
				return nil
			})

			targetNS.Do(func(ns.NetNS) error {
				// Validate that the ENI is no longer in the target netns
				_, err := netlink.LinkByName(ifName)
				assert.EqualError(t, err, "Link not found")
				return nil
			})

		})
	}
}

// newConfig creates a new config object
func newConfig() (*config, error) {
	ec2Metadata := ec2metadata.New(session.Must(session.NewSession()))
	region, err := ec2Metadata.Region()
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get region from ec2 metadata")
	}

	instanceID, err := ec2Metadata.GetMetadata("instance-id")
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get instance id from ec2 metadata")
	}

	mac, err := ec2Metadata.GetMetadata("mac")
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get mac from ec2 metadata")
	}

	securityGroups, err := ec2Metadata.GetMetadata("security-groups")
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get security groups from ec2 metadata")
	}

	interfaces, err := ec2Metadata.GetMetadata("network/interfaces/macs")
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get interfaces from ec2 metadata")
	}

	subnet, err := ec2Metadata.GetMetadata("network/interfaces/macs/" + mac + "/subnet-id")
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get subnet from ec2 metadata")
	}

	vpc, err := ec2Metadata.GetMetadata("network/interfaces/macs/" + mac + "/vpc-id")
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get vpc from ec2 metadata")
	}

	return &config{region: region,
		subnet:         subnet,
		index:          int64(len(strings.Split(interfaces, "\n"))),
		instanceID:     instanceID,
		securityGroups: strings.Split(securityGroups, "\n"),
		vpc:            vpc,
	}, nil
}

// createENI creates an ENI in the same subnet as the instance's primary ENI
func createENI(ec2Client *ec2.EC2, cfg *config) (*ec2.NetworkInterface, error) {
	var filterValuesGroupName []*string
	for _, sg := range cfg.securityGroups {
		filterValuesGroupName = append(filterValuesGroupName, aws.String(sg))
	}
	// Get security group id for the security group that the instance was
	// started with
	securityGroups, err := ec2Client.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("group-name"),
				Values: filterValuesGroupName,
			},
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{aws.String(cfg.vpc)},
			},
		}})
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get security group ids")
	}
	var securityGroupIDs []*string
	for _, sg := range securityGroups.SecurityGroups {
		securityGroupIDs = append(securityGroupIDs, sg.GroupId)
	}

	// Create the ENI
	output, err := ec2Client.CreateNetworkInterface(&ec2.CreateNetworkInterfaceInput{
		Description: aws.String("for running end-to-end test for VPC ENI Plugin"),
		Groups:      securityGroupIDs,
		SubnetId:    aws.String(cfg.subnet),
	})
	if err != nil {
		return nil, errors.Wrapf(err, "unable to create network interface")
	}
	return output.NetworkInterface, nil
}

// computeIPv4SubnetGatewayAndPrefixLength computes the IPv4 subnet gateway
// and prefix length of the ENI
func computeIPv4SubnetGatewayAndPrefixLength(
	ec2Client *ec2.EC2,
	subnetID string,
) (string, string, error) {
	resp, err := ec2Client.DescribeSubnets(&ec2.DescribeSubnetsInput{
		SubnetIds: []*string{aws.String(subnetID)},
	})
	if err != nil {
		return "", "", errors.Wrapf(err, "unable to describe the subnet")
	}
	if len(resp.Subnets) != 1 {
		return "", "", errors.Errorf(
			"unexpected number of subnets returned in describe: %d", len(resp.Subnets))
	}

	// The IPV4 CIDR block is of the format ip-addr/netmask
	cidrBlock := aws.StringValue(resp.Subnets[0].CidrBlock)
	ip, ipNet, err := net.ParseCIDR(cidrBlock)
	if err != nil {
		return "", "", errors.Wrapf(err,
			"compute ipv4 gateway netmask: unable to parse cidr: '%s'", cidrBlock)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return "", "", fmt.Errorf("unable to parse ipv4 gateway from cidr block '%s'", cidrBlock)
	}

	maskOnes, _ := ipNet.Mask.Size()

	// ipv4 gateway is the first available IP address in the subnet
	ip4[3] = ip4[3] + 1

	return ip4.String(), fmt.Sprintf("%d", maskOnes), nil
}

// waitUntilNetworkInterfaceAvailable waits until the ENI state == "available"
func waitUntilNetworkInterfaceAvailable(ec2Client *ec2.EC2, eni *ec2.NetworkInterface) error {
	return ec2Client.WaitUntilNetworkInterfaceAvailable(&ec2.DescribeNetworkInterfacesInput{
		Filters: []*ec2.Filter{{
			Name:   aws.String("network-interface-id"),
			Values: []*string{eni.NetworkInterfaceId}},
		}})
}

// deleteENI deletes the ENI
func deleteENI(ec2Client *ec2.EC2, eni *ec2.NetworkInterface) error {
	err := waitUntilNetworkInterfaceAvailable(ec2Client, eni)
	if err != nil {
		return errors.Wrapf(err, "failed waiting for ENI to be 'available'")
	}
	_, err = ec2Client.DeleteNetworkInterface(&ec2.DeleteNetworkInterfaceInput{
		NetworkInterfaceId: eni.NetworkInterfaceId,
	})
	if err != nil {
		return errors.Wrapf(err, "unable to deleye ENI")
	}
	return nil
}

// attachENI attaches the ENI to the current EC2 instance
func attachENI(ec2Client *ec2.EC2, cfg *config, eni *ec2.NetworkInterface) (*ec2.AttachNetworkInterfaceOutput, error) {
	return ec2Client.AttachNetworkInterface(&ec2.AttachNetworkInterfaceInput{
		DeviceIndex:        aws.Int64(cfg.index),
		InstanceId:         aws.String(cfg.instanceID),
		NetworkInterfaceId: eni.NetworkInterfaceId,
	})
}

// detachENI detaches the ENI from the current EC2 instance
func detachENI(ec2Client *ec2.EC2, attachment *ec2.AttachNetworkInterfaceOutput) error {
	_, err := ec2Client.DetachNetworkInterface(&ec2.DetachNetworkInterfaceInput{
		AttachmentId: attachment.AttachmentId,
		Force:        aws.Bool(true),
	})

	if err != nil {
		errors.Wrapf(err, "unable to detach ENI")
	}
	return nil
}

// waitUntilNetworkInterfaceAttached waits until the ENI shows up on the instance
func waitUntilNetworkInterfaceAttached(
	eni *ec2.NetworkInterface,
	interval time.Duration,
) (string, error) {
	for {
		links, err := netlink.LinkList()
		if err != nil {
			return "", err
		}
		for _, link := range links {
			if link.Attrs().HardwareAddr.String() == aws.StringValue(eni.MacAddress) {
				return link.Attrs().Name, nil
			}
		}
		time.Sleep(interval)
	}
}

// validateTargetNSRoutes validates routes in the target network namespace
func validateTargetNSRoutes(t *testing.T) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	require.NoError(t, err, "Unable to list routes")

	var imdsRouteFound, gatewayRouteFound bool
	for _, route := range routes {
		if route.Gw == nil && route.Dst.String() == imdsEndpoint {
			imdsRouteFound = true
		}
		if route.Gw != nil && route.Dst == nil {
			gatewayRouteFound = true
		}
	}

	require.True(t, imdsRouteFound, "Blocking route for instance metadata not found ")
	require.True(t, gatewayRouteFound, "Route to use the vpc subnet gateway not found ")
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
