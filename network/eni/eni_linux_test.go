package eni

import (
	"errors"
	"net"
	"testing"

	"github.com/aws/amazon-vpc-cni-plugins/network/netns/mocks"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

func TestSetLinkName(t *testing.T) {
	testENI, mockNetLink, _, ctrl := NewMockENI(t)
	ctrl.Finish()

	mockNetLink.EXPECT().LinkSetName(gomock.Any(), gomock.Any()).Do(func(link *netlink.Dummy, name string) {
		assert.Equal(t, link.LinkAttrs.Name, testLinkName)
		assert.Equal(t, name, "testNewLinkName")
	}).Return(nil)

	err := testENI.SetLinkName("testNewLinkName")
	assert.NoError(t, err)
	assert.Equal(t, "testNewLinkName", testENI.linkName)
}

func TestSetLinkNameError(t *testing.T) {
	testENI, mockNetLink, _, ctrl := NewMockENI(t)
	ctrl.Finish()

	mockNetLink.EXPECT().LinkSetName(gomock.Any(), gomock.Any()).Return(errors.New("test error"))

	err := testENI.SetLinkName("testNewLinkName")
	assert.Error(t, err)
}

func TestSetLinkMTU(t *testing.T) {
	testENI, mockNetLink, _, ctrl := NewMockENI(t)
	ctrl.Finish()

	mockNetLink.EXPECT().LinkSetMTU(gomock.Any(), gomock.Any()).Do(func(link *netlink.Dummy, mtu int) {
		assert.Equal(t, link.LinkAttrs.Name, testLinkName)
		assert.Equal(t, mtu, 100)
	}).Return(nil)

	err := testENI.SetLinkMTU(uint(100))
	assert.NoError(t, err)
}

func TestSetLinkMTUError(t *testing.T) {
	testENI, mockNetLink, _, ctrl := NewMockENI(t)
	ctrl.Finish()

	mockNetLink.EXPECT().LinkSetMTU(gomock.Any(), gomock.Any()).Return(errors.New("test error"))

	err := testENI.SetLinkMTU(uint(100))
	assert.Error(t, err)
}

func TestSetOpStateUp(t *testing.T) {
	testENI, mockNetLink, _, ctrl := NewMockENI(t)
	ctrl.Finish()

	mockNetLink.EXPECT().LinkSetUp(gomock.Any()).Do(func(link *netlink.Dummy) {
		assert.Equal(t, link.LinkAttrs.Name, testLinkName)
	}).Return(nil)

	err := testENI.SetOpState(true)
	assert.NoError(t, err)
}

func TestSetOpStateUpError(t *testing.T) {
	testENI, mockNetLink, _, ctrl := NewMockENI(t)
	ctrl.Finish()

	mockNetLink.EXPECT().LinkSetUp(gomock.Any()).Return(errors.New("test error"))

	err := testENI.SetOpState(true)
	assert.Error(t, err)
}

func TestSetOpStateDown(t *testing.T) {
	testENI, mockNetLink, _, ctrl := NewMockENI(t)
	ctrl.Finish()

	mockNetLink.EXPECT().LinkSetDown(gomock.Any()).Do(func(link *netlink.Dummy) {
		assert.Equal(t, link.LinkAttrs.Name, testLinkName)
	}).Return(nil)

	err := testENI.SetOpState(false)
	assert.NoError(t, err)
}

func TestSetOpStateDownError(t *testing.T) {
	testENI, mockNetLink, _, ctrl := NewMockENI(t)
	ctrl.Finish()

	mockNetLink.EXPECT().LinkSetDown(gomock.Any()).Return(errors.New("test error"))

	err := testENI.SetOpState(false)
	assert.Error(t, err)
}

func TestSetNetNS(t *testing.T) {
	testENI, mockNetLink, _, ctrl := NewMockENI(t)
	ctrl.Finish()

	mockNetNS := mock_netns.NewMockNetNS(ctrl)

	gomock.InOrder(
		mockNetNS.EXPECT().GetFd().Return(uintptr(1)),
		mockNetLink.EXPECT().LinkSetNsFd(gomock.Any(), gomock.Any()).Do(func(link *netlink.Dummy, fd int) {
			assert.Equal(t, link.LinkAttrs.Name, testLinkName)
			assert.Equal(t, 1, fd)
		}).Return(nil),
	)

	err := testENI.SetNetNS(mockNetNS)
	assert.NoError(t, err)
}

func TestSetNetNSError(t *testing.T) {
	testENI, mockNetLink, _, ctrl := NewMockENI(t)
	ctrl.Finish()

	mockNetNS := mock_netns.NewMockNetNS(ctrl)

	gomock.InOrder(
		mockNetNS.EXPECT().GetFd().Return(uintptr(1)),
		mockNetLink.EXPECT().LinkSetNsFd(gomock.Any(), gomock.Any()).Return(errors.New("test error")),
	)

	err := testENI.SetNetNS(mockNetNS)
	assert.Error(t, err)
}

func TestSetMACAddress(t *testing.T) {
	testENI, mockNetLink, _, ctrl := NewMockENI(t)
	ctrl.Finish()

	testNewMACAddress, _ := net.ParseMAC("cb:a9:87:65:43:21")

	mockNetLink.EXPECT().LinkSetHardwareAddr(gomock.Any(), gomock.Any()).Do(func(link *netlink.Dummy, address net.HardwareAddr) {
		assert.Equal(t, link.LinkAttrs.Name, testLinkName)
		assert.Equal(t, testNewMACAddress, address)
	}).Return(nil)

	err := testENI.SetMACAddress(testNewMACAddress)
	assert.NoError(t, err)
}

func TestSetMACAddressError(t *testing.T) {
	testENI, mockNetLink, _, ctrl := NewMockENI(t)
	ctrl.Finish()

	testNewMACAddress, _ := net.ParseMAC("cb:a9:87:65:43:21")

	mockNetLink.EXPECT().LinkSetHardwareAddr(gomock.Any(), gomock.Any()).Return(errors.New("test error"))

	err := testENI.SetMACAddress(testNewMACAddress)
	assert.Error(t, err)
}

func TestSetIPAddress(t *testing.T) {
	testENI, mockNetLink, _, ctrl := NewMockENI(t)
	ctrl.Finish()

	_, testNetwork, _ := net.ParseCIDR("172.0.0.1/24")

	mockNetLink.EXPECT().AddrAdd(gomock.Any(), gomock.Any()).Do(func(link *netlink.Dummy, addr *netlink.Addr) {
		assert.Equal(t, testLinkIndex, link.LinkAttrs.Index)
		assert.Equal(t, testNetwork, addr.IPNet)
	}).Return(nil)

	err := testENI.SetIPAddress(testNetwork)
	assert.NoError(t, err)
}

func TestSetIPAddressError(t *testing.T) {
	testENI, mockNetLink, _, ctrl := NewMockENI(t)
	ctrl.Finish()

	_, testNetwork, _ := net.ParseCIDR("172.0.0.1/24")

	mockNetLink.EXPECT().AddrAdd(gomock.Any(), gomock.Any()).Return(errors.New("test error"))

	err := testENI.SetIPAddress(testNetwork)
	assert.Error(t, err)
}
