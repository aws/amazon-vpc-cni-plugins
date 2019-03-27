package plugin

import (
	"errors"
	"net"
	"testing"

	"github.com/aws/amazon-vpc-cni-plugins/cni"
	"github.com/aws/amazon-vpc-cni-plugins/network/cniwrapper/mocks"
	"github.com/aws/amazon-vpc-cni-plugins/network/eni"
	"github.com/aws/amazon-vpc-cni-plugins/network/eniwrapper/mocks"
	"github.com/aws/amazon-vpc-cni-plugins/network/netlinkwrapper/mocks"
	"github.com/aws/amazon-vpc-cni-plugins/network/netns/mocks"
	"github.com/aws/amazon-vpc-cni-plugins/network/netwrapper/mocks"
	"github.com/containernetworking/cni/pkg/skel"
	cniTypesCurrent "github.com/containernetworking/cni/pkg/types/current"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

const (
	testValidConfig    = `{"trunkName":"eth0", "branchVlanID":"101", "branchMACAddress":"01:23:45:67:89:ab", "branchIPAddress":"10.11.12.13/16", "branchGatewayIPAddress":"10.11.0.1", "interfaceType":"vlan"}`
	testInvalidConfig  = `{"trunkName":"eth1"}`
	testNetNS          = "testNetNS"
	testFD             = uintptr(1)
	expectedBranchName = "eth0.101"
)

// setup creates a test Plugin object and related mocks needed for testing.
func setup(t *testing.T) (*Plugin, *skel.CmdArgs, *eni.Branch, *eni.Trunk, *mock_eniwrapper.MockENI, *mock_netlinkwrapper.MockNetLink,
	*mock_netns.MockNetNS, *mock_netns.MockNetNSProvider, *mock_cniwrapper.MockCNI, *gomock.Controller) {
	ctrl := gomock.NewController(t)
	mockENI := mock_eniwrapper.NewMockENI(ctrl)
	mockNet := mock_netwrapper.NewMockNet(ctrl)
	mockNetLink := mock_netlinkwrapper.NewMockNetLink(ctrl)
	mockNetNS := mock_netns.NewMockNetNS(ctrl)
	mockNetNSProvider := mock_netns.NewMockNetNSProvider(ctrl)
	mockCNI := mock_cniwrapper.NewMockCNI(ctrl)

	plugin := &Plugin{&cni.Plugin{
		ENIWrapper:     mockENI,
		NetLinkWrapper: mockNetLink,
		NetNSProvider:  mockNetNSProvider,
		CNIWrapper:     mockCNI,
	}}

	args := &skel.CmdArgs{
		StdinData: []byte(testValidConfig),
		Args:      "",
		Netns:     testNetNS,
		IfName:    testIfName,
	}

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

	return plugin, args, testBranch, testTrunk, mockENI, mockNetLink, mockNetNS, mockNetNSProvider, mockCNI, ctrl
}

func TestAddCommand(t *testing.T) {
	plugin, args, testBranch, testTrunk, mockENI, mockNetLink, mockNetNS, mockNetNSProvider, mockCNI, ctrl := setup(t)
	ctrl.Finish()

	gomock.InOrder(
		mockNetNSProvider.EXPECT().GetNetNS(testNetNS).Return(mockNetNS, nil),
		mockENI.EXPECT().NewTrunk("eth0", gomock.Any(), eni.TrunkIsolationModeVLAN).Return(testTrunk, nil),
		mockENI.EXPECT().NewBranch(testTrunk, expectedBranchName, testBranch.GetMACAddress(), testBranchIsolationID).Return(testBranch, nil),
		mockNetLink.EXPECT().LinkAdd(gomock.Any()).Do(func(vlan *netlink.Vlan) {
			assert.Equal(t, testLinkName, vlan.LinkAttrs.Name)
			assert.Equal(t, testBranchIsolationID, vlan.VlanId)
		}).Return(nil),
		mockNetLink.EXPECT().LinkSetHardwareAddr(gomock.Any(), gomock.Any()).Do(func(vlan *netlink.Vlan, hwaddr net.HardwareAddr) {
			assert.Equal(t, testLinkName, vlan.LinkAttrs.Name)
			assert.Equal(t, hwaddr, testBranch.GetMACAddress())
		}).Return(nil),
		mockNetNS.EXPECT().GetFd().Return(testFD),
		mockNetLink.EXPECT().LinkSetNsFd(gomock.Any(), gomock.Any()).Do(func(link *netlink.Dummy, fd int) {
			assert.Equal(t, testLinkName, link.LinkAttrs.Name)
			assert.Equal(t, fd, int(testFD))
		}).Return(nil),
		mockNetNS.EXPECT().Run(gomock.Any()).Return(nil),
		mockCNI.EXPECT().PrintResult(gomock.Any(), gomock.Any()).Do(func(result *cniTypesCurrent.Result, version string) {
			assert.Equal(t, 1, len(result.Interfaces))
			assert.Equal(t, testIfName, result.Interfaces[0].Name)
			assert.Equal(t, testMacAddressString, result.Interfaces[0].Mac)
			assert.Equal(t, testNetNS, result.Interfaces[0].Sandbox)
		}).Return(nil),
	)

	err := plugin.Add(args)
	assert.NoError(t, err)
}

func TestAddCommandFailsOnConfigInit(t *testing.T) {
	plugin, args, _, _, _, _, _, _, _, ctrl := setup(t)
	ctrl.Finish()

	args.StdinData = []byte(testInvalidConfig)

	err := plugin.Add(args)
	assert.Error(t, err)
}

func TestAddCommentFailsOnGetNetNS(t *testing.T) {
	plugin, args, _, _, _, _, _, mockNetNSProvider, _, ctrl := setup(t)
	ctrl.Finish()

	gomock.InOrder(
		mockNetNSProvider.EXPECT().GetNetNS(testNetNS).Return(nil, errors.New("test error")),
	)

	err := plugin.Add(args)
	assert.Error(t, err)
}

func TestAddCommentFailsOnTrunkInit(t *testing.T) {
	plugin, args, _, _, mockENI, _, mockNetNS, mockNetNSProvider, _, ctrl := setup(t)
	ctrl.Finish()

	gomock.InOrder(
		mockNetNSProvider.EXPECT().GetNetNS(testNetNS).Return(mockNetNS, nil),
		mockENI.EXPECT().NewTrunk("eth0", gomock.Any(), eni.TrunkIsolationModeVLAN).Return(nil, errors.New("test error")),
	)

	err := plugin.Add(args)
	assert.Error(t, err)
}

func TestAddCommentFailsOnBranchInit(t *testing.T) {
	plugin, args, testBranch, testTrunk, mockENI, _, mockNetNS, mockNetNSProvider, _, ctrl := setup(t)
	ctrl.Finish()

	gomock.InOrder(
		mockNetNSProvider.EXPECT().GetNetNS(testNetNS).Return(mockNetNS, nil),
		mockENI.EXPECT().NewTrunk("eth0", gomock.Any(), eni.TrunkIsolationModeVLAN).Return(testTrunk, nil),
		mockENI.EXPECT().NewBranch(testTrunk, expectedBranchName, testBranch.GetMACAddress(),
			testBranchIsolationID).Return(nil, errors.New("test error")),
	)

	err := plugin.Add(args)
	assert.Error(t, err)
}

func TestAddCommentFailsOnAttachToLink(t *testing.T) {
	plugin, args, testBranch, testTrunk, mockENI, mockNetLink, mockNetNS, mockNetNSProvider, _, ctrl := setup(t)
	ctrl.Finish()

	gomock.InOrder(
		mockNetNSProvider.EXPECT().GetNetNS(testNetNS).Return(mockNetNS, nil),
		mockENI.EXPECT().NewTrunk("eth0", gomock.Any(), eni.TrunkIsolationModeVLAN).Return(testTrunk, nil),
		mockENI.EXPECT().NewBranch(testTrunk, expectedBranchName, testBranch.GetMACAddress(),
			testBranchIsolationID).Return(testBranch, nil),
		mockNetLink.EXPECT().LinkAdd(gomock.Any()).Return(errors.New("test error")),
	)

	err := plugin.Add(args)
	assert.Error(t, err)
}

func TestAddCommentFailsOnSetNetNS(t *testing.T) {
	plugin, args, testBranch, testTrunk, mockENI, mockNetLink, mockNetNS, mockNetNSProvider, _, ctrl := setup(t)
	ctrl.Finish()

	gomock.InOrder(
		mockNetNSProvider.EXPECT().GetNetNS(testNetNS).Return(mockNetNS, nil),
		mockENI.EXPECT().NewTrunk("eth0", gomock.Any(), eni.TrunkIsolationModeVLAN).Return(testTrunk, nil),
		mockENI.EXPECT().NewBranch(testTrunk, expectedBranchName, testBranch.GetMACAddress(),
			testBranchIsolationID).Return(testBranch, nil),
		mockNetLink.EXPECT().LinkAdd(gomock.Any()).Do(func(vlan *netlink.Vlan) {
			assert.Equal(t, testLinkName, vlan.LinkAttrs.Name)
			assert.Equal(t, testBranchIsolationID, vlan.VlanId)
		}).Return(nil),
		mockNetLink.EXPECT().LinkSetHardwareAddr(gomock.Any(), gomock.Any()).Do(func(vlan *netlink.Vlan, hwaddr net.HardwareAddr) {
			assert.Equal(t, testLinkName, vlan.LinkAttrs.Name)
			assert.Equal(t, hwaddr, testBranch.GetMACAddress())
		}).Return(nil),
		mockNetNS.EXPECT().GetFd().Return(testFD),
		mockNetLink.EXPECT().LinkSetNsFd(gomock.Any(), gomock.Any()).Return(errors.New("test error")),
	)

	err := plugin.Add(args)
	assert.Error(t, err)
}

func TestAddCommentFailsOnNSRun(t *testing.T) {
	plugin, args, testBranch, testTrunk, mockENI, mockNetLink, mockNetNS, mockNetNSProvider, _, ctrl := setup(t)
	ctrl.Finish()

	gomock.InOrder(
		mockNetNSProvider.EXPECT().GetNetNS(testNetNS).Return(mockNetNS, nil),
		mockENI.EXPECT().NewTrunk("eth0", gomock.Any(), eni.TrunkIsolationModeVLAN).Return(testTrunk, nil),
		mockENI.EXPECT().NewBranch(testTrunk, expectedBranchName, testBranch.GetMACAddress(),
			testBranchIsolationID).Return(testBranch, nil),
		mockNetLink.EXPECT().LinkAdd(gomock.Any()).Do(func(vlan *netlink.Vlan) {
			assert.Equal(t, testLinkName, vlan.LinkAttrs.Name)
			assert.Equal(t, testBranchIsolationID, vlan.VlanId)
		}).Return(nil),
		mockNetLink.EXPECT().LinkSetHardwareAddr(gomock.Any(), gomock.Any()).Do(func(vlan *netlink.Vlan, hwaddr net.HardwareAddr) {
			assert.Equal(t, testLinkName, vlan.LinkAttrs.Name)
			assert.Equal(t, hwaddr, testBranch.GetMACAddress())
		}).Return(nil),
		mockNetNS.EXPECT().GetFd().Return(testFD),
		mockNetLink.EXPECT().LinkSetNsFd(gomock.Any(), gomock.Any()).Do(func(link *netlink.Dummy, fd int) {
			assert.Equal(t, testLinkName, link.LinkAttrs.Name)
			assert.Equal(t, fd, int(testFD))
		}).Return(nil),
		mockNetNS.EXPECT().Run(gomock.Any()).Return(errors.New("test error")),
	)

	err := plugin.Add(args)
	assert.Error(t, err)
}

func TestAddCommentFailsOnPrintResult(t *testing.T) {
	plugin, args, testBranch, testTrunk, mockENI, mockNetLink, mockNetNS, mockNetNSProvider, mockCNI, ctrl := setup(t)
	ctrl.Finish()

	gomock.InOrder(
		mockNetNSProvider.EXPECT().GetNetNS(testNetNS).Return(mockNetNS, nil),
		mockENI.EXPECT().NewTrunk("eth0", gomock.Any(), eni.TrunkIsolationModeVLAN).Return(testTrunk, nil),
		mockENI.EXPECT().NewBranch(testTrunk, expectedBranchName, testBranch.GetMACAddress(),
			testBranchIsolationID).Return(testBranch, nil),
		mockNetLink.EXPECT().LinkAdd(gomock.Any()).Do(func(vlan *netlink.Vlan) {
			assert.Equal(t, testLinkName, vlan.LinkAttrs.Name)
			assert.Equal(t, testBranchIsolationID, vlan.VlanId)
		}).Return(nil),
		mockNetLink.EXPECT().LinkSetHardwareAddr(gomock.Any(), gomock.Any()).Do(func(vlan *netlink.Vlan, hwaddr net.HardwareAddr) {
			assert.Equal(t, testLinkName, vlan.LinkAttrs.Name)
			assert.Equal(t, hwaddr, testBranch.GetMACAddress())
		}).Return(nil),
		mockNetNS.EXPECT().GetFd().Return(testFD),
		mockNetLink.EXPECT().LinkSetNsFd(gomock.Any(), gomock.Any()).Do(func(link *netlink.Dummy, fd int) {
			assert.Equal(t, testLinkName, link.LinkAttrs.Name)
			assert.Equal(t, fd, int(testFD))
		}).Return(nil),
		mockNetNS.EXPECT().Run(gomock.Any()).Return(nil),
		mockCNI.EXPECT().PrintResult(gomock.Any(), gomock.Any()).Return(errors.New("test error")),
	)

	err := plugin.Add(args)
	assert.Error(t, err)
}
