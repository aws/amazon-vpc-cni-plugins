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

// +build linux

package eni

import (
	"errors"
	"net"
	"testing"

	"github.com/aws/amazon-vpc-cni-plugins/network/netlinkwrapper/mocks"
	"github.com/aws/amazon-vpc-cni-plugins/network/netwrapper/mocks"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

const testBranchIsolationID = 101

// NewMockBranch creates a test Branch object and related mocks needed for testing.
func NewMockBranch(t *testing.T) (*Branch, *mock_netlinkwrapper.MockNetLink, *gomock.Controller) {
	testMacAddress, _ := net.ParseMAC(testMacAddressString)
	ctrl := gomock.NewController(t)
	mockNetLink := mock_netlinkwrapper.NewMockNetLink(ctrl)
	mockNet := mock_netwrapper.NewMockNet(ctrl)
	testENI := &ENI{
		linkIndex:      testLinkIndex,
		linkName:       testLinkName,
		macAddress:     testMacAddress,
		netLinkWrapper: mockNetLink,
		netWrapper:     mockNet,
	}

	testTrunk := &Trunk{
		ENI:           *testENI,
		isolationMode: TrunkIsolationModeVLAN,
	}

	testBranch := &Branch{
		ENI:         *testENI,
		isolationID: testBranchIsolationID,
		trunk:       testTrunk,
	}

	return testBranch, mockNetLink, ctrl
}

func TestAttachToLinkSetMACAddress(t *testing.T) {
	branch, mockNetLink, ctrl := NewMockBranch(t)
	defer ctrl.Finish()

	gomock.InOrder(
		mockNetLink.EXPECT().LinkAdd(gomock.Any()).Do(func(vlan *netlink.Vlan){
			assert.Equal(t, testLinkName, vlan.LinkAttrs.Name)
			assert.Equal(t, testLinkIndex, vlan.LinkAttrs.ParentIndex)
			assert.Equal(t, testBranchIsolationID, vlan.VlanId)
		}).Return(nil),
		mockNetLink.EXPECT().LinkSetHardwareAddr(gomock.Any(), gomock.Any()).Do(func(vlan *netlink.Vlan, addr net.HardwareAddr){
			assert.Equal(t, testLinkName, vlan.LinkAttrs.Name)
			assert.Equal(t, testLinkIndex, vlan.LinkAttrs.ParentIndex)
			assert.Equal(t, testBranchIsolationID, vlan.VlanId)
			assert.Equal(t, branch.macAddress, addr)
		}).Return(nil),
	)

	err := branch.AttachToLink(true)
	assert.NoError(t, err)
}

func TestAttachToLinkWithoutSetMACAddress(t *testing.T) {
	branch, mockNetLink, ctrl := NewMockBranch(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkAdd(gomock.Any()).Do(func(vlan *netlink.Vlan){
		assert.Equal(t, testLinkName, vlan.LinkAttrs.Name)
		assert.Equal(t, testLinkIndex, vlan.LinkAttrs.ParentIndex)
		assert.Equal(t, testBranchIsolationID, vlan.VlanId)
	}).Return(nil)

	err := branch.AttachToLink(false)
	assert.NoError(t, err)
}

func TestAttachToLinkAddLinkError(t *testing.T) {
	branch, mockNetLink, ctrl := NewMockBranch(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkAdd(gomock.Any()).Return(errors.New("test error"))

	err := branch.AttachToLink(true)
	assert.Error(t, err)
}

func TestAttachToLinkSetMACAddressError(t *testing.T) {
	branch, mockNetLink, ctrl := NewMockBranch(t)
	defer ctrl.Finish()

	gomock.InOrder(
		mockNetLink.EXPECT().LinkAdd(gomock.Any()).Do(func(vlan *netlink.Vlan){
			assert.Equal(t, testLinkName, vlan.LinkAttrs.Name)
			assert.Equal(t, testLinkIndex, vlan.LinkAttrs.ParentIndex)
			assert.Equal(t, testBranchIsolationID, vlan.VlanId)
		}).Return(nil),
		mockNetLink.EXPECT().LinkSetHardwareAddr(gomock.Any(), gomock.Any()).Return(errors.New("test error")),
	)

	err := branch.AttachToLink(true)
	assert.Error(t, err)
}

func TestDetachFromLink(t *testing.T) {
	branch, mockNetLink, ctrl := NewMockBranch(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkDel(gomock.Any()).Do(func(vlan *netlink.Vlan){
		assert.Equal(t, testLinkName, vlan.LinkAttrs.Name)
		assert.Equal(t, testLinkIndex, vlan.LinkAttrs.ParentIndex)
		assert.Equal(t, testBranchIsolationID, vlan.VlanId)
	}).Return(nil)

	err := branch.DetachFromLink()
	assert.NoError(t, err)
	assert.Equal(t, 0, branch.linkIndex)
}

func TestDetachFromLinkDeleteLinkError(t *testing.T) {
	branch, mockNetLink, ctrl := NewMockBranch(t)
	defer ctrl.Finish()

	mockNetLink.EXPECT().LinkDel(gomock.Any()).Return(errors.New("test error"))

	err := branch.DetachFromLink()
	assert.Error(t, err)
}
