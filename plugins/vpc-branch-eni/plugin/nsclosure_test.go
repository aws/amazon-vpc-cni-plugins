// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package plugin

import (
	"errors"
	"net"
	"testing"

	"github.com/aws/amazon-vpc-cni-plugins/network/eni"
	"github.com/aws/amazon-vpc-cni-plugins/network/netlinkwrapper/mocks"
	"github.com/aws/amazon-vpc-cni-plugins/network/netwrapper/mocks"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-branch-eni/config"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

const (
	testLinkName              = "eth0"
	testMacAddressString      = "01:23:45:67:89:ab"
	testBranchIsolationID     = 101
	testBranchName            = "testBranchName"
	testBranchIPString        = "172.0.0.3/24"
	testBranchGatewayIPString = "172.0.0.1"
	testIfName                = "testIfName"
	testUID                   = 1
)

// setupSetupNamespaceClosure creates a test setupNamespaceClosureContext object and related mocks needed for testing.
func setupSetupNamespaceClosure(t *testing.T) (*setupNamespaceClosureContext, *mock_netlinkwrapper.MockNetLink, *gomock.Controller) {
	ctrl := gomock.NewController(t)
	mockNetLink := mock_netlinkwrapper.NewMockNetLink(ctrl)
	mockNet := mock_netwrapper.NewMockNet(ctrl)

	testBranch, testNetConfig := setupCommon(t, mockNetLink, mockNet)

	closureContext := &setupNamespaceClosureContext{
		branch:     testBranch,
		branchName: testBranchName,
		ifName:     testIfName,
		netConfig:  testNetConfig,
		netLink:    mockNetLink,
		uid:        testUID,
	}

	return closureContext, mockNetLink, ctrl
}

// setupTeardownNamespaceClosure creates a test teardownNamespaceClosureContext object and related mocks needed for testing.
func setupTeardownNamespaceClosure(t *testing.T) (*teardownNamespaceClosureContext, *mock_netlinkwrapper.MockNetLink, *gomock.Controller) {
	ctrl := gomock.NewController(t)
	mockNetLink := mock_netlinkwrapper.NewMockNetLink(ctrl)
	mockNet := mock_netwrapper.NewMockNet(ctrl)

	_, testNetConfig := setupCommon(t, mockNetLink, mockNet)

	closureContext := &teardownNamespaceClosureContext{
		branchName: testBranchName,
		netConfig:  testNetConfig,
		netLink:    mockNetLink,
	}

	return closureContext, mockNetLink, ctrl
}

// setupCommon contains the common setup steps used by setupSetupNamespaceClosure and setupTeardownNamespaceClosure.
func setupCommon(t *testing.T, mockNetLink *mock_netlinkwrapper.MockNetLink,
	mockNet *mock_netwrapper.MockNet) (*eni.Branch, *config.NetConfig) {
	testMacAddress, _ := net.ParseMAC(testMacAddressString)
	testENI, err := eni.NewENIWithWrappers(testLinkName, testMacAddress, mockNetLink, mockNet)
	require.NoError(t, err)

	mockNet.EXPECT().InterfaceByName(testLinkName).Return(&net.Interface{
		Name:         testLinkName,
		HardwareAddr: testENI.GetMACAddress(),
	}, nil)
	testTrunk, err := eni.NewTrunkWithENI(testENI, eni.TrunkIsolationModeVLAN)
	require.NoError(t, err)

	testBranch, err := eni.NewBranchWithENI(testENI, testTrunk, testBranchIsolationID)
	require.NoError(t, err)

	_, testBranchIP, _ := net.ParseCIDR(testBranchIPString)
	testBranchGatewayIP := net.ParseIP(testBranchGatewayIPString)

	testNetConfig := &config.NetConfig{
		InterfaceType:          config.IfTypeVLAN,
		BranchIPAddress:        testBranchIP,
		BranchGatewayIPAddress: testBranchGatewayIP,
		BranchVlanID:           testBranchIsolationID,
	}

	return testBranch, testNetConfig
}

func TestSetupNamespaceVLANLink(t *testing.T) {
	closureContext, mockNetLink, ctrl := setupSetupNamespaceClosure(t)
	defer ctrl.Finish()
	gomock.InOrder(
		mockNetLink.EXPECT().LinkSetName(gomock.Any(), gomock.Any()).Do(func(netLink *netlink.Dummy, name string) {
			assert.Equal(t, testLinkName, netLink.LinkAttrs.Name)
			assert.Equal(t, testIfName, name)
		}).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(gomock.Any()).Do(func(netLink *netlink.Dummy) {
			assert.Equal(t, testIfName, netLink.LinkAttrs.Name)
		}).Return(nil),
		mockNetLink.EXPECT().AddrAdd(gomock.Any(), gomock.Any()).Do(func(netLink *netlink.Dummy, addr *netlink.Addr) {
			assert.Equal(t, closureContext.netConfig.BranchIPAddress, addr.IPNet)
		}).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, closureContext.netConfig.BranchGatewayIPAddress, route.Gw)
		}).Return(nil),
	)

	err := closureContext.run()
	assert.NoError(t, err)
	assert.Equal(t, testIfName, closureContext.branch.GetLinkName())
}

func TestSetupNamespaceBlockIMDS(t *testing.T) {
	closureContext, mockNetLink, ctrl := setupSetupNamespaceClosure(t)
	closureContext.netConfig.BlockIMDS = true

	defer ctrl.Finish()
	gomock.InOrder(
		mockNetLink.EXPECT().LinkSetName(gomock.Any(), gomock.Any()).Do(func(netLink *netlink.Dummy, name string) {
			assert.Equal(t, testLinkName, netLink.LinkAttrs.Name)
			assert.Equal(t, testIfName, name)
		}).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(gomock.Any()).Do(func(netLink *netlink.Dummy) {
			assert.Equal(t, testIfName, netLink.LinkAttrs.Name)
		}).Return(nil),
		mockNetLink.EXPECT().AddrAdd(gomock.Any(), gomock.Any()).Do(func(netLink *netlink.Dummy, addr *netlink.Addr) {
			assert.Equal(t, closureContext.netConfig.BranchIPAddress, addr.IPNet)
		}).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, closureContext.netConfig.BranchGatewayIPAddress, route.Gw)
		}).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Return(nil),
	)

	err := closureContext.run()
	assert.NoError(t, err)
	assert.Equal(t, testIfName, closureContext.branch.GetLinkName())
}

func TestSetupNamespaceBlockIMDSFails(t *testing.T) {
	closureContext, mockNetLink, ctrl := setupSetupNamespaceClosure(t)
	closureContext.netConfig.BlockIMDS = true

	defer ctrl.Finish()
	gomock.InOrder(
		mockNetLink.EXPECT().LinkSetName(gomock.Any(), gomock.Any()).Do(func(netLink *netlink.Dummy, name string) {
			assert.Equal(t, testLinkName, netLink.LinkAttrs.Name)
			assert.Equal(t, testIfName, name)
		}).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(gomock.Any()).Do(func(netLink *netlink.Dummy) {
			assert.Equal(t, testIfName, netLink.LinkAttrs.Name)
		}).Return(nil),
		mockNetLink.EXPECT().AddrAdd(gomock.Any(), gomock.Any()).Do(func(netLink *netlink.Dummy, addr *netlink.Addr) {
			assert.Equal(t, closureContext.netConfig.BranchIPAddress, addr.IPNet)
		}).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, closureContext.netConfig.BranchGatewayIPAddress, route.Gw)
		}).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Return(errors.New("test error")),
	)

	err := closureContext.run()
	assert.Error(t, err)
}

func TestTearDownNamespace(t *testing.T) {
	closureContext, mockNetLink, ctrl := setupTeardownNamespaceClosure(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkDel(gomock.Any()).Do(func(vlan *netlink.Vlan) {
		assert.Equal(t, testBranchName, vlan.LinkAttrs.Name)
	}).Return(nil)

	err := closureContext.run()
	assert.NoError(t, err)
}

func TestTearDownNamespaceFailsOnLinkDel(t *testing.T) {
	closureContext, mockNetLink, ctrl := setupTeardownNamespaceClosure(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkDel(gomock.Any()).Return(errors.New("test error"))

	err := closureContext.run()
	assert.Error(t, err)
}

func TestCreateVLANLinkWithIP(t *testing.T) {
	closureContext, mockNetLink, ctrl := setupSetupNamespaceClosure(t)
	defer ctrl.Finish()

	gomock.InOrder(
		mockNetLink.EXPECT().LinkSetName(gomock.Any(), gomock.Any()).Do(func(netLink *netlink.Dummy, name string) {
			assert.Equal(t, testLinkName, netLink.LinkAttrs.Name)
			assert.Equal(t, testIfName, name)
		}).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(gomock.Any()).Do(func(netLink *netlink.Dummy) {
			assert.Equal(t, testIfName, netLink.LinkAttrs.Name)
		}).Return(nil),
		mockNetLink.EXPECT().AddrAdd(gomock.Any(), gomock.Any()).Do(func(netLink *netlink.Dummy, addr *netlink.Addr) {
			assert.Equal(t, closureContext.netConfig.BranchIPAddress, addr.IPNet)
		}).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Do(func(route *netlink.Route) {
			assert.Equal(t, closureContext.netConfig.BranchGatewayIPAddress, route.Gw)
		}).Return(nil),
	)

	err := closureContext.createVLANLink(closureContext.branch, testIfName, closureContext.netConfig.BranchIPAddress,
		closureContext.netConfig.BranchGatewayIPAddress)
	assert.NoError(t, err)
	assert.Equal(t, testIfName, closureContext.branch.GetLinkName())
}

func TestCreateVLANLinkWithoutIP(t *testing.T) {
	closureContext, mockNetLink, ctrl := setupSetupNamespaceClosure(t)
	defer ctrl.Finish()

	gomock.InOrder(
		mockNetLink.EXPECT().LinkSetName(gomock.Any(), gomock.Any()).Do(func(netLink *netlink.Dummy, name string) {
			assert.Equal(t, testLinkName, netLink.LinkAttrs.Name)
			assert.Equal(t, testIfName, name)
		}).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(gomock.Any()).Do(func(netLink *netlink.Dummy) {
			assert.Equal(t, testIfName, netLink.LinkAttrs.Name)
		}).Return(nil),
	)

	err := closureContext.createVLANLink(closureContext.branch, testIfName, nil, nil)
	assert.NoError(t, err)
	assert.Equal(t, testIfName, closureContext.branch.GetLinkName())
}

func TestCreateVLANLinkFailsOnSetLinkName(t *testing.T) {
	closureContext, mockNetLink, ctrl := setupSetupNamespaceClosure(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkSetName(gomock.Any(), gomock.Any()).Return(errors.New("test error"))

	err := closureContext.createVLANLink(closureContext.branch, testIfName, closureContext.netConfig.BranchIPAddress,
		closureContext.netConfig.BranchGatewayIPAddress)
	assert.Error(t, err)
}

func TestCreateVLANLinkFailsOnSetOpState(t *testing.T) {
	closureContext, mockNetLink, ctrl := setupSetupNamespaceClosure(t)
	defer ctrl.Finish()

	gomock.InOrder(
		mockNetLink.EXPECT().LinkSetName(gomock.Any(), gomock.Any()).Do(func(netLink *netlink.Dummy, name string) {
			assert.Equal(t, testLinkName, netLink.LinkAttrs.Name)
			assert.Equal(t, testIfName, name)
		}).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(gomock.Any()).Return(errors.New("test error")),
	)

	err := closureContext.createVLANLink(closureContext.branch, testIfName, closureContext.netConfig.BranchIPAddress,
		closureContext.netConfig.BranchGatewayIPAddress)
	assert.Error(t, err)
}

func TestCreateVLANLinkFailsOnSetIPAddress(t *testing.T) {
	closureContext, mockNetLink, ctrl := setupSetupNamespaceClosure(t)
	defer ctrl.Finish()

	gomock.InOrder(
		mockNetLink.EXPECT().LinkSetName(gomock.Any(), gomock.Any()).Do(func(netLink *netlink.Dummy, name string) {
			assert.Equal(t, testLinkName, netLink.LinkAttrs.Name)
			assert.Equal(t, testIfName, name)
		}).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(gomock.Any()).Do(func(netLink *netlink.Dummy) {
			assert.Equal(t, testIfName, netLink.LinkAttrs.Name)
		}).Return(nil),
		mockNetLink.EXPECT().AddrAdd(gomock.Any(), gomock.Any()).Return(errors.New("test error")),
	)

	err := closureContext.createVLANLink(closureContext.branch, testIfName, closureContext.netConfig.BranchIPAddress,
		closureContext.netConfig.BranchGatewayIPAddress)
	assert.Error(t, err)
}

func TestCreateVLANLinkFailsOnRouteAdd(t *testing.T) {
	closureContext, mockNetLink, ctrl := setupSetupNamespaceClosure(t)
	defer ctrl.Finish()

	gomock.InOrder(
		mockNetLink.EXPECT().LinkSetName(gomock.Any(), gomock.Any()).Do(func(netLink *netlink.Dummy, name string) {
			assert.Equal(t, testLinkName, netLink.LinkAttrs.Name)
			assert.Equal(t, testIfName, name)
		}).Return(nil),
		mockNetLink.EXPECT().LinkSetUp(gomock.Any()).Do(func(netLink *netlink.Dummy) {
			assert.Equal(t, testIfName, netLink.LinkAttrs.Name)
		}).Return(nil),
		mockNetLink.EXPECT().AddrAdd(gomock.Any(), gomock.Any()).Do(func(netLink *netlink.Dummy, addr *netlink.Addr) {
			assert.Equal(t, closureContext.netConfig.BranchIPAddress, addr.IPNet)
		}).Return(nil),
		mockNetLink.EXPECT().RouteAdd(gomock.Any()).Return(errors.New("test error")),
	)

	err := closureContext.createVLANLink(closureContext.branch, testIfName, closureContext.netConfig.BranchIPAddress,
		closureContext.netConfig.BranchGatewayIPAddress)
	assert.Error(t, err)
}
