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

//go:build e2e_test
// +build e2e_test

package e2e

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/ecs-serviceconnect/config"

	cniInvoke "github.com/containernetworking/cni/pkg/invoke"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesCurrent "github.com/containernetworking/cni/pkg/types/100"
	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	cniSpecVersion    = "1.0.0"
	nsName            = "ecs-sc-testNS"
	containerID       = "contain-er"
	ingressChain      = "ECS_SERVICE_CONNECT_INGRESS"
	egressTproxyChain = "ECS_SERVICE_CONNECT_DIVERT"
	pluginName        = "ecs-serviceconnect"
)

var (
	pluginPath string
)

// TestValid tests when network configuration is valid.
func TestValid(t *testing.T) {
	var err error
	pluginPath, err = cniInvoke.FindInPath(pluginName, []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, fmt.Sprintf("Unable to find %s plugin in path", pluginName))

	testLogDir, preserve := setupLogs(t, "TestValid")
	defer func(preserve bool) {
		if !t.Failed() && !preserve {
			os.RemoveAll(testLogDir)
		}
	}(preserve)

	for _, filePath := range []string{
		"valid_empty_ingress",
		"valid_ingress_with_port_intercept_1",
		"valid_ingress_with_port_intercept_2",
		"valid_ingress_without_port_intercept",
		"valid_tproxy_redirect_ip",
		"valid_tproxy_redirect_port",
		"valid_without_egress",
		"valid_without_ingress",
	} {
		t.Run(filePath, func(t *testing.T) {
			testValid(t, filePath)
		})
	}
}

// TestInvalid tests when network configuration is invalid.
func TestInvalid(t *testing.T) {
	var err error
	pluginPath, err = cniInvoke.FindInPath(pluginName, []string{os.Getenv("CNI_PATH")})
	require.NoError(t, err, fmt.Sprintf("Unable to find %s plugin in path", pluginName))

	testLogDir, preserve := setupLogs(t, "TestInValid")
	defer func(preserve bool) {
		if !t.Failed() && !preserve {
			os.RemoveAll(testLogDir)
		}
	}(preserve)

	for filename, errorMsg := range map[string]string{
		"invalid_egress_ipv4_cidr_1":            "invalid parameter: EgressConfig IPv4 CIDR Address",
		"invalid_egress_ipv4_cidr_2":            "invalid parameter: EgressConfig IPv4 CIDR Address",
		"invalid_egress_ipv6_cidr_1":            "invalid parameter: EgressConfig IPv6 CIDR Address",
		"invalid_egress_ipv6_cidr_2":            "invalid parameter: EgressConfig IPv6 CIDR Address",
		"invalid_egress_listener_port":          "invalid port -1 specified",
		"invalid_egress_redirect_ip_1":          "invalid parameter: EgressConfig RedirectIP",
		"invalid_egress_redirect_ip_2":          "missing required parameter: EgressConfig Redirect IP",
		"invalid_egress_redirect_ip_3":          "missing required parameter: Egress ListenerPort",
		"invalid_empty_egress":                  "exactly one of ListenerPort and RedirectIP must be specified in Egress",
		"invalid_empty_egress_vip":              "missing required parameter: EgressConfig VIP CIDR",
		"invalid_ingress_intercept_port":        "invalid port -1 specified",
		"invalid_ingress_listener_port":         "invalid port 80000 specified",
		"invalid_missing_egress_listener_port":  "exactly one of ListenerPort and RedirectIP must be specified in Egress",
		"invalid_missing_egress_vip":            "missing required parameter: EgressConfig VIP",
		"invalid_missing_ingress_egress":        "either IngressConfig or EgressConfig must be present",
		"invalid_missing_ingress_listener_port": "invalid port 0 specified",
		"invalid_v6_missing_egress_vip":         "missing required parameter: EgressConfig VIP CIDR",
		"invalid_missing_ip":                    "both V4 and V6 cannot be disabled",
		"invalid_missing_redirect_mode":         "invalid parameter: Egress RedirectMode",
		"invalid_redirect_mode":                 "invalid parameter: Egress RedirectMode",
	} {
		t.Run(filename, func(t *testing.T) {
			testInvalid(t, filename, errorMsg)
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
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bytes
}

// testValid verifies that CNI ADD and DEL command succeed.
func testValid(t *testing.T, filename string) {
	netConfData := loadTestData(t, filename)
	ctx := context.Background()
	netConf, err := config.New(&cniSkel.CmdArgs{
		StdinData: netConfData,
	})
	require.NoError(t, err, "Unable to create NetConfig object for provided netConf string")

	// Create a network namespace to mimic the container's network namespace.
	targetNS, err := netns.NewNetNS(nsName)
	require.NoError(t, err,
		"Unable to create the network namespace for the container")
	defer targetNS.Close()

	err = targetNS.Run(func() error {
		link, err := netlink.LinkByName("lo")
		if err != nil {
			t.Logf("Unable to get the loopback interface")
			return err
		}
		// Bring the interface up.
		if err := netlink.LinkSetUp(link); err != nil {
			t.Logf("Unable to setup loopback interface")
			return err
		}
		return nil
	})
	require.NoError(t, err, "Failed to setup interface")

	// Construct args to invoke the CNI plugin with.
	execInvokeArgs := &cniInvoke.Args{
		ContainerID: containerID,
		NetNS:       targetNS.GetPath(),
		IfName:      "test",
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
	require.NoError(t, err, "Unable to execute ADD command for ecs-serviceconnect CNI plugin")

	validateResults(t, res)

	targetNS.Run(func() error {
		// Validate IP rules successfully added.
		validateIPRulesAdded(t, netConf)
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
	require.NoError(t, err, "Unable to execute DEL command for ecs-serviceconnect CNI plugin")

	targetNS.Run(func() error {
		// Validate IP rules successfully deleted.
		validateIPRulesDeleted(t, netConf)
		return nil
	})
}

func validateResults(t *testing.T, result cniTypes.Result) {
	// Test that the plugin passed previous CNI result unmodified.
	res, err := result.GetAsVersion(cniSpecVersion)
	assert.NoError(t, err, "Unable to parse result")
	r := res.(*cniTypesCurrent.Result)
	assert.Equal(t, 0, len(r.IPs))
	assert.Equal(t, 0, len(r.Routes))
}

// validateIPRulesAdded validates IP rules created in the target network namespace.
func validateIPRulesAdded(t *testing.T, netConf *config.NetConfig) {
	for proto, mustExist := range getProto(netConf) {
		iptable, err := iptables.NewWithProtocol(proto)
		require.NoError(t, err, "Unable to initialize iptable")

		validateIngressIptableRulesAdded(t, iptable, netConf,
			mustExist && len(netConf.IngressListenerToInterceptPortMap) > 0)

		validateEgressIptableRulesAdded(t, iptable, proto, netConf,
			mustExist && netConf.EgressPort != 0)
	}
}

// validateIngressIptableRulesAdded validates the IP table rules that are added for handling ingress traffic.
func validateIngressIptableRulesAdded(t *testing.T, iptable *iptables.IPTables,
	netConf *config.NetConfig, mustExist bool) {
	for redirectPort, listenerPort := range netConf.IngressListenerToInterceptPortMap {
		exist, _ := iptable.Exists("nat", ingressChain, "-p", "tcp", "--dport",
			strconv.Itoa(listenerPort), "-j", "REDIRECT", "--to-port", strconv.Itoa(redirectPort))
		require.Equal(t, mustExist, exist, "Mismatch of expected rules to redirect ingress ports")

		exist, _ = iptable.Exists("nat", "PREROUTING", "-p", "tcp", "-m", "addrtype", "!",
			"--src-type", "LOCAL", "-j", ingressChain)
		require.Equal(t, mustExist, exist, "Mismatch of expected rules to redirect non-local traffic")
	}
}

// getCidr returns the Cidr for the protocol.
func getCidr(proto iptables.Protocol, netConf *config.NetConfig) string {
	var cidr string
	if proto == iptables.ProtocolIPv4 {
		cidr = netConf.EgressIPv4CIDR
	} else {
		cidr = netConf.EgressIPv6CIDR
	}
	return cidr
}

// validateEgressIptableRulesAdded validates the IP table rules that are added for handling egress traffic.
func validateEgressIptableRulesAdded(t *testing.T, iptable *iptables.IPTables, proto iptables.Protocol,
	netConf *config.NetConfig, mustExist bool) {
	switch netConf.EgressRedirectMode {
	case config.NAT:
		exist, _ := iptable.Exists("nat", "OUTPUT", "-p", "tcp", "-d", getCidr(proto, netConf),
			"-j", "REDIRECT", "--to-port", strconv.Itoa(netConf.EgressPort))
		require.Equal(t, mustExist, exist, "Mismatch in expected rules to redirect ports")
	case config.TPROXY:
		if netConf.EgressRedirectIPv4Addr != "" || netConf.EgressRedirectIPv6Addr != "" {
			verifyEgressRedirectIP(t, proto, netConf, true)
		} else {
			verifyEgressTproxyRules(t, iptable, proto, netConf, true)
		}
	}
}

// verifyEgressRedirectIP validates the rules set in the case of Tproxy Redirection IP
func verifyEgressRedirectIP(t *testing.T, proto iptables.Protocol, netConf *config.NetConfig, mustExist bool) {
	handle, err := netlink.NewHandle()
	require.NoError(t, err, "Failed to get new handle")

	var dst *net.IPNet
	var redirectionIP net.IP
	if proto == iptables.ProtocolIPv6 {
		_, dst, _ = net.ParseCIDR(netConf.EgressIPv6CIDR)
		redirectionIP = net.ParseIP(netConf.EgressRedirectIPv6Addr)
	} else {
		_, dst, _ = net.ParseCIDR(netConf.EgressIPv4CIDR)
		redirectionIP = net.ParseIP(netConf.EgressRedirectIPv4Addr)
	}

	route := &netlink.Route{
		Dst: dst,
		Gw:  redirectionIP,
	}
	family := getFamily(proto)
	_, err = handle.RouteListFiltered(family, route, netlink.RT_FILTER_GW|netlink.RT_FILTER_DST)
	require.NoError(t, err, "Failed to list routes")
}

// verifyEgressTproxyRules validates the presence or absence of all the rules needed for Tproxy redirection.
func verifyEgressTproxyRules(t *testing.T, iptable *iptables.IPTables, proto iptables.Protocol,
	netConf *config.NetConfig, mustExist bool) {
	exist, _ := iptable.Exists("mangle", egressTproxyChain, "-j", "MARK", "--set-mark", "1")
	require.Equal(t, mustExist, exist, "Mismatch in expected rules for tproxy mark")
	exist, _ = iptable.Exists("mangle", egressTproxyChain, "-j", "ACCEPT")
	require.Equal(t, mustExist, exist, "Mismatch in expected rules for tproxy chain")
	exist, _ = iptable.Exists("mangle", "PREROUTING", "-p", "tcp", "-m",
		"socket", "-j", egressTproxyChain)
	require.Equal(t, mustExist, exist, "Mismatch in expected rules for prerouting chain")
	exist, _ = iptable.Exists("mangle", "PREROUTING", "-p", "tcp",
		"-m", "tcp", "-d", getCidr(proto, netConf), "-j", "TPROXY", "--tproxy-mark", "0x1/0x1", "--on-port",
		strconv.Itoa(netConf.EgressPort))
	require.Equal(t, mustExist, exist, "Mismatch in expected rules for prerouting chain")
	handle, err := netlink.NewHandle()
	require.NoError(t, err, "Failed to get new handle")
	family := getFamily(proto)
	allRules, err := handle.RuleList(family)
	require.NoError(t, err, "Failed to list all ip rules")
	rule := netlink.NewRule()
	rule.Family = family
	rule.Mark = 1
	rule.Table = 100
	require.Equal(t, mustExist, ruleExists(t, allRules, rule), "Mismatch in expected rules")
	link, err := netlink.LinkByName("lo")
	require.NoError(t, err, "Failed to get loopback interface")

	route := &netlink.Route{
		Table:     100,
		LinkIndex: link.Attrs().Index,
	}
	routes, err := handle.RouteListFiltered(family, route, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
	require.Equal(t, 1, len(routes))
}

// getFamily returns the family given the protocol.
func getFamily(proto iptables.Protocol) int {
	if proto == iptables.ProtocolIPv6 {
		return unix.AF_INET6
	} else {
		return unix.AF_INET
	}
}

// ruleExists verifies whether the given rule exists in the given list of rules.
func ruleExists(t *testing.T, rules []netlink.Rule, rule *netlink.Rule) bool {
	for i := range rules {
		if ruleEquals(t, &rules[i], rule) {
			return true
		}
	}
	return false
}

// ruleEquals returns whether the given rules can be considered equal.
func ruleEquals(t *testing.T, a, b *netlink.Rule) bool {
	return a.Table == b.Table &&
		((a.Src == nil && b.Src == nil) ||
			(a.Src != nil && b.Src != nil && a.Src.String() == b.Src.String())) &&
		((a.Dst == nil && b.Dst == nil) ||
			(a.Dst != nil && b.Dst != nil && a.Dst.String() == b.Dst.String())) &&
		a.OifName == b.OifName &&
		a.IifName == b.IifName &&
		a.Invert == b.Invert &&
		a.Mark == b.Mark &&
		a.TunID == b.TunID &&
		a.Goto == b.Goto
}

// getProto returns map of protocol and whether it needs to be handled.
func getProto(netConf *config.NetConfig) map[iptables.Protocol]bool {
	protoMap := make(map[iptables.Protocol]bool)
	if netConf.EgressIPv4CIDR != "" {
		protoMap[iptables.ProtocolIPv4] = true
	}
	if netConf.EgressIPv6CIDR != "" {
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

		validateEgressIptableRulesDeleted(t, iptable, proto, netConf)
	}
}

// validateIngressIptableRulesDeleted validates that the ingress IP rules do not exist.
func validateIngressIptableRulesDeleted(t *testing.T, iptable *iptables.IPTables, netConf *config.NetConfig) {
	for redirectPort, listenerPort := range netConf.IngressListenerToInterceptPortMap {
		exist, _ := iptable.Exists("nat", ingressChain, "-p", "tcp", "--dport",
			strconv.Itoa(listenerPort), "-j", "REDIRECT", "--to-port", strconv.Itoa(redirectPort))
		require.False(t, exist, "Found unexpected rules to redirect ingress ports")

		exist, _ = iptable.Exists("nat", "PREROUTING", "-p", "tcp", "-m", "addrtype", "!",
			"--src-type", "LOCAL", "-j", ingressChain)
		require.False(t, exist, "Found unexpected rules to redirect non-local traffic")
	}
}

// validateEgressIptableRulesDeleted validates that the egress IP rules do not exist.
func validateEgressIptableRulesDeleted(t *testing.T, iptable *iptables.IPTables, proto iptables.Protocol,
	netConf *config.NetConfig) {
	switch netConf.EgressRedirectMode {
	case config.NAT:
		exist, _ := iptable.Exists("nat", "OUTPUT", "-p", "tcp", "-d", getCidr(proto, netConf),
			"-j", "REDIRECT", "--to-port", strconv.Itoa(netConf.EgressPort))
		require.False(t, exist, "Found unexpected rules to redirect cidr")
	case config.TPROXY:
		if netConf.EgressRedirectIPv4Addr != "" || netConf.EgressRedirectIPv6Addr != "" {
			verifyEgressRedirectIP(t, proto, netConf, false)
		} else {
			verifyEgressTproxyRules(t, iptable, proto, netConf, false)
		}
	}
}

// testInvalid tests whether the test file returns the given error.
func testInvalid(t *testing.T,
	filename string,
	errorMsg string) {
	netConfData := loadTestData(t, filename)

	// Create a network namespace to mimic the container's network namespace.
	targetNS, err := netns.NewNetNS(nsName)
	ctx := context.Background()
	require.NoError(t, err,
		"Unable to create the network namespace that represents the network namespace of the container")
	defer targetNS.Close()

	// Construct args to invoke the CNI plugin with.
	execInvokeArgs := &cniInvoke.Args{
		ContainerID: containerID,
		NetNS:       targetNS.GetPath(),
		IfName:      "test",
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
	assert.EqualError(t, err, errorMsg)
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

// setupLogs sets up the log environment for cni executable and returns the log directory
// and a bool that represents whether to preserve logfiles after execution.
func setupLogs(t *testing.T, testCase string) (string, bool) {
	// Create a directory for storing test logs.
	testLogDir, err := os.MkdirTemp("", pluginName+"-cni-e2eTests-test")
	err = os.Chmod(testLogDir, 0755)
	require.NoError(t, err, "Unable to create directory for storing test logs")

	// Configure the env var to use the test logs directory.
	os.Setenv("VPC_CNI_LOG_FILE", fmt.Sprintf("%s/%s.log", testLogDir, testCase))
	t.Logf("Using %s for test logs", testLogDir)

	// Handle deletion of test logs at the end of the test execution if specified.
	ok, err := strconv.ParseBool(getEnvOrDefault("ECS_PRESERVE_E2E_TEST_LOGS", "false"))
	assert.NoError(t, err, "Unable to parse ECS_PRESERVE_E2E_TEST_LOGS env var")
	return testLogDir, ok
}
