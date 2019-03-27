package imds

import (
	"errors"
	"testing"

	"github.com/aws/amazon-vpc-cni-plugins/network/netlinkwrapper/mocks"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestBlockInstanceMetadataEndpoint(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockNetLink := mock_netlinkwrapper.NewMockNetLink(ctrl)
	defer ctrl.Finish()

	mockNetLink.EXPECT().RouteAdd(gomock.Any()).Return(nil)

	err := BlockInstanceMetadataEndpoint(mockNetLink)
	assert.NoError(t, err)
}

func TestBlockInstanceMetadataEndpointFailsOnRouteAdd(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockNetLink := mock_netlinkwrapper.NewMockNetLink(ctrl)
	defer ctrl.Finish()

	mockNetLink.EXPECT().RouteAdd(gomock.Any()).Return(errors.New("test error"))

	err := BlockInstanceMetadataEndpoint(mockNetLink)
	assert.Error(t, err)
}
