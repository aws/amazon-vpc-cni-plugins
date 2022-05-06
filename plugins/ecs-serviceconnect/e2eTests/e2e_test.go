// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

// +build e2e_test, ecs_serviceconnect

package e2e

import (
	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/ecs-serviceconnect/config"
	testutils "github.com/aws/amazon-vpc-cni-plugins/plugins/utils/test"
	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

const (
	nsName       = "testNS"
	containerID  = "contain-er"
	ifName       = "test"
	ingressChain = "ECS_SERVICE_CONNECT_INGRESS"
	egressChain  = "ECS_SERVICE_CONNECT_EGRESS"
)

var (
	pluginPath string
)

// TestValid tests when network configuration is valid.
func TestValid(t *testing.T) {
	var err error
	pluginPath, err = invoke.FindInPath("ecs-serviceconnect", []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, "Unable to find ecs-serviceconnect plugin in path")

	testutils.SetupPluginEnvironment(t, "ecs-serviceconnect")

	for _, filename := range []string{
		"valid_empty_ingress",
		"valid_ingress_with_port_intercept_1",
		"valid_ingress_with_port_intercept_2",
		"valid_ingress_without_port_intercept",
		"valid_without_egress",
		"valid_without_ingress",
	} {
		t.Run(filename, func(t *testing.T) {
			testValid(t, filename)
		})
	}
}

// loadTestData loads test cases in json form.
func loadTestData(t *testing.T, name string) []byte {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(wd), "testdata", name+".json")
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes
}

// testValid verifies that cni ADD and DEL command succeed.
func testValid(t *testing.T, filename string) {
	netConfData := loadTestData(t, filename)
	netConf, err := config.New(&skel.CmdArgs{
		StdinData: netConfData,
	})
	require.NoError(t, err, "Unable to create NetConfig object for provided netConf string")

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

	// Execute the "ADD" command for the plugin.
	execInvokeArgs.Command = "ADD"
	err = invoke.ExecPluginWithoutResult(
		pluginPath,
		netConfData,
		execInvokeArgs)
	require.NoError(t, err, "Unable to execute ADD command for ecs-serviceconnect cni plugin")

	targetNS.Run(func() error {
		// Validate IP rules successfully added.
		validateIPRulesAdded(t, netConf)
		return nil
	})

	// Execute the "DEL" command for the plugin.
	execInvokeArgs.Command = "DEL"
	err = invoke.ExecPluginWithoutResult(
		pluginPath,
		netConfData,
		execInvokeArgs)
	require.NoError(t, err, "Unable to execute DEL command for ecs-serviceconnect cni plugin")

	targetNS.Run(func() error {
		// Validate IP rules successfully deleted.
		validateIPRulesDeleted(t, netConf)
		return nil
	})
}

// validateIPRulesAdded validates IP rules created in the target network namespace.
func validateIPRulesAdded(t *testing.T, netConf *config.NetConfig) {
	for proto, mustExist := range getProto(netConf) {
		iptable, err := iptables.NewWithProtocol(proto)
		require.NoError(t, err, "Unable to initialize iptable")

		validateIngressIptableRulesAdded(t, iptable, netConf,
			mustExist && len(netConf.IngressRedirectToListenerPortMap) > 0)

		//TODO: Add support for BRIDGE_TPROXY
		switch netConf.Mode {
		case config.AWSVPC, config.BRIDGE_DNAT:
			validateEgressIptableRulesAdded(t, iptable, proto, netConf,
				mustExist && netConf.EgressPort != 0)
		}
	}
}

// validateIngressIptableRulesAdded validates the IP table rules that are added for handling ingress traffic
func validateIngressIptableRulesAdded(t *testing.T, iptable *iptables.IPTables, netConf *config.NetConfig, mustExist bool) {
	for redirectPort, listenerPorts := range netConf.IngressRedirectToListenerPortMap {
		exist, _ := iptable.Exists("nat", ingressChain, "-p", "tcp", "-m", "multiport", "--dports", listenerPorts,
			"-j", "REDIRECT", "--to-port", redirectPort)
		require.Equal(t, mustExist, exist, "Mismatch of expected rules to redirect ingress ports")

		exist, _ = iptable.Exists("nat", "PREROUTING", "-p", "tcp", "-m", "addrtype", "!",
			"--src-type", "LOCAL", "-j", ingressChain)
		require.Equal(t, mustExist, exist, "Mismatch of expected rules to redirect non-local traffic")
	}
}

// getCidr returns the Cidr for the protocol
func getCidr(proto iptables.Protocol, netConf *config.NetConfig) string {
	var cidr string
	if proto == iptables.ProtocolIPv4 {
		cidr = netConf.EgressIPV4CIDR
	} else {
		cidr = netConf.EgressIPV6CIDR
	}
	return cidr
}

// validateEgressIptableRulesAdded validates the IP table rules that are added for handling egress traffic
func validateEgressIptableRulesAdded(t *testing.T, iptable *iptables.IPTables, proto iptables.Protocol, netConf *config.NetConfig, mustExist bool) {

	exist, _ := iptable.Exists("nat", "OUTPUT", "-p", "tcp", "-d", getCidr(proto, netConf),
		"-j", "REDIRECT", "--to-port", strconv.Itoa(netConf.EgressPort))
	require.Equal(t, mustExist, exist, "Mismatch in expected rules to redirect ports")
}

// getProto returns map of protocol and whether it needs to be handled
func getProto(netConf *config.NetConfig) map[iptables.Protocol]bool {
	protoMap := make(map[iptables.Protocol]bool)
	if netConf.EgressIPV4CIDR != "" {
		protoMap[iptables.ProtocolIPv4] = true
	}
	if netConf.EgressIPV6CIDR != "" {
		protoMap[iptables.ProtocolIPv4] = true
	}
	return protoMap
}

// validateIPRulesDeleted validates IP rules deleted in the target network namespace.
func validateIPRulesDeleted(t *testing.T, netConf *config.NetConfig) {
	for proto, _ := range getProto(netConf) {
		iptable, err := iptables.NewWithProtocol(proto)
		require.NoError(t, err, "Unable to initialize iptable")

		validateIngressIptableRulesDeleted(t, iptable, netConf)

		//TODO: Add support for BRIDGE_TPROXY
		switch netConf.Mode {
		case config.AWSVPC, config.BRIDGE_DNAT:
			validateEgressIptableRulesDeleted(t, iptable, proto, netConf)
		}
	}
}

// validateIngressIptableRulesDeleted validates that the ingress IP rules do not exist
func validateIngressIptableRulesDeleted(t *testing.T, iptable *iptables.IPTables, netConf *config.NetConfig) {
	for redirectPort, listenerPorts := range netConf.IngressRedirectToListenerPortMap {
		exist, _ := iptable.Exists("nat", ingressChain, "-p", "tcp", "-m", "multiport", "--dports", listenerPorts,
			"-j", "REDIRECT", "--to-port", redirectPort)
		require.False(t, exist, "Found unexpected rules to redirect ingress ports")

		exist, _ = iptable.Exists("nat", "PREROUTING", "-p", "tcp", "-m", "addrtype", "!",
			"--src-type", "LOCAL", "-j", ingressChain)
		require.False(t, exist, "Found unexpected rules to redirect non-local traffic")
	}
}

func validateEgressIptableRulesDeleted(t *testing.T, iptable *iptables.IPTables, proto iptables.Protocol, netConf *config.NetConfig) {

	exist, _ := iptable.Exists("nat", "OUTPUT", "-p", "tcp", "-d", getCidr(proto, netConf),
		"-j", "REDIRECT", "--to-port", strconv.Itoa(netConf.EgressPort))
	require.False(t, exist, "Found unexpected rules to redirect cidr")
}

// TestInvalid tests when network configuration is invalid.
func TestInvalid(t *testing.T) {
	var err error
	pluginPath, err = invoke.FindInPath("ecs-serviceconnect", []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, "Unable to find ecs-serviceconnect plugin in path")

	testutils.SetupPluginEnvironment(t, "ecs-serviceconnect")
	for filename, error := range map[string]string{
		"invalid_egress_ipv4_cidr_1":            "missing required parameter: EgressConfig IPV4 VIP CIDR Address",
		"invalid_egress_ipv4_cidr_2":            "invalid parameter: EgressConfig IPv4 CIDR Address",
		"invalid_egress_ipv6_cidr_1":            "invalid parameter: EgressConfig IPv6 CIDR Address",
		"invalid_egress_ipv6_cidr_2":            "invalid parameter: EgressConfig IPv6 CIDR Address",
		"invalid_egress_listener_port":          "invalid port [-1] specified",
		"invalid_empty_egress":                  "invalid port [0] specified",
		"invalid_empty_egress_vip":              "missing required parameter: EgressConfig IPV4 VIP CIDR Address",
		"invalid_ingress_intercept_port":        "invalid port [-1] specified",
		"invalid_ingress_listener_port":         "invalid port [80000] specified",
		"invalid_missing_egress_listener_port":  "invalid port [0] specified",
		"invalid_missing_egress_vip":            "missing required parameter: EgressConfig VIP",
		"invalid_missing_ingress_egress":        "either IngressConfig or EgressConfig must be present",
		"invalid_missing_ingress_listener_port": "invalid port [0] specified",
		"invalid_missing_network":               "missing required parameter: NetworkConfig",
		"invalid_network":                       "invalid value for NetworkConfig",
	} {
		t.Run(filename, func(t *testing.T) {
			testInvalid(t, filename, error)
		})
	}
}

func testInvalid(t *testing.T,
	filename string,
	error string) {
	netConfData := loadTestData(t, filename)

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

	// Execute the "ADD" command for the plugin.
	execInvokeArgs.Command = "ADD"
	err = invoke.ExecPluginWithoutResult(
		pluginPath,
		netConfData,
		execInvokeArgs)
	assert.EqualError(t, err, error)

}
