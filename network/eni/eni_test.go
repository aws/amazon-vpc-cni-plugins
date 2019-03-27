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

package eni

import (
	"errors"
	"net"
	"testing"

	"github.com/aws/amazon-vpc-cni-plugins/network/netlinkwrapper/mocks"
	"github.com/aws/amazon-vpc-cni-plugins/network/netwrapper/mocks"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

const (
	testLinkIndex        = 1
	testLinkName         = "eth0"
	testMacAddressString = "12:34:56:78:9a:bc"
)

// NewMockENI creates a test ENI object and related mocks needed for testing.
func NewMockENI(t *testing.T) (*ENI, *mock_netlinkwrapper.MockNetLink, *mock_netwrapper.MockNet, *gomock.Controller) {
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

	return testENI, mockNetLink, mockNet, ctrl
}

func TestNewENI(t *testing.T) {
	testENI, _, _, _ := NewMockENI(t)
	testMacAddress := testENI.macAddress

	eni, err := NewENI(testLinkName, testMacAddress)
	assert.NoError(t, err)
	assert.Equal(t, eni.linkName, testLinkName)
	assert.Equal(t, eni.macAddress, testMacAddress)
}

func TestNewENINoLinkNameOrMacAddress(t *testing.T) {
	_, err := NewENI("", nil)
	assert.Error(t, err)
}

func TestGetLinkIndex(t *testing.T) {
	testENI, _, _, _ := NewMockENI(t)
	assert.Equal(t, testLinkIndex, testENI.GetLinkIndex())
}

func TestGetLinkName(t *testing.T) {
	testENI, _, _, _ := NewMockENI(t)
	assert.Equal(t, testLinkName, testENI.GetLinkName())
}

func TestGetMacAddress(t *testing.T) {
	testENI, _, _, _ := NewMockENI(t)
	assert.Equal(t, testENI.macAddress, testENI.GetMACAddress())
}

func TestString(t *testing.T) {
	testENI, _, _, _ := NewMockENI(t)
	assert.Equal(t, "{linkName:eth0 macAddress:12:34:56:78:9a:bc}", testENI.String())
}

func TestAttachToLinkWithLinkName(t *testing.T) {
	testENI, _, mockNet, ctrl := NewMockENI(t)
	defer ctrl.Finish()

	ifHardwareAddr, _ := net.ParseMAC("cb:a9:87:65:43:21")
	mockNet.EXPECT().InterfaceByName(testENI.linkName).Return(&net.Interface{
		Index:        1,
		Name:         "ifName",
		HardwareAddr: ifHardwareAddr,
	}, nil)

	err := testENI.AttachToLink()
	assert.NoError(t, err)
	assert.Equal(t, 1, testENI.linkIndex)
	assert.Equal(t, "ifName", testENI.linkName)
	assert.Equal(t, ifHardwareAddr, testENI.macAddress)
}

func TestAttachToLinkWithLinkNameFindInterfaceError(t *testing.T) {
	testENI, _, mockNet, ctrl := NewMockENI(t)
	defer ctrl.Finish()

	mockNet.EXPECT().InterfaceByName(testENI.linkName).Return(nil, errors.New("test error"))

	err := testENI.AttachToLink()
	assert.Error(t, err)
}

func TestAttachToLinkWithoutLinkName(t *testing.T) {
	testENI, _, mockNet, ctrl := NewMockENI(t)
	defer ctrl.Finish()

	testENI.linkName = ""

	ifHardwareAddr, _ := net.ParseMAC(testMacAddressString)
	mockNet.EXPECT().Interfaces().Return([]net.Interface{
		{
			Index:        1,
			Name:         "ifName",
			HardwareAddr: ifHardwareAddr,
		},
	}, nil)

	err := testENI.AttachToLink()
	assert.NoError(t, err)
	assert.Equal(t, 1, testENI.linkIndex)
	assert.Equal(t, "ifName", testENI.linkName)
	assert.Equal(t, ifHardwareAddr, testENI.macAddress)
}

func TestAttachToLinkWithoutLinkNameListInterfacesError(t *testing.T) {
	testENI, _, mockNet, ctrl := NewMockENI(t)
	defer ctrl.Finish()

	testENI.linkName = ""

	mockNet.EXPECT().Interfaces().Return(nil, errors.New("test error"))

	err := testENI.AttachToLink()
	assert.Error(t, err)
}

func TestAttachToLinkWithoutLinkNameListInterfacesEmpty(t *testing.T) {
	testENI, _, mockNet, ctrl := NewMockENI(t)
	defer ctrl.Finish()

	testENI.linkName = ""

	mockNet.EXPECT().Interfaces().Return([]net.Interface{}, nil)

	err := testENI.AttachToLink()
	assert.Error(t, err)

}
