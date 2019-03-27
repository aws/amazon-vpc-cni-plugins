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

package imds

import (
	"net"
	"syscall"

	"github.com/aws/amazon-vpc-cni-plugins/network/netlinkwrapper"
	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"

	log "github.com/cihub/seelog"
	"github.com/vishvananda/netlink"
)

// BlockInstanceMetadataEndpoint adds a blackhole rule for IMDS endpoint.
func BlockInstanceMetadataEndpoint(netLink netlinkwrapper.NetLink) error {
	log.Infof("Adding route to block instance metadata endpoint %s", vpc.InstanceMetadataEndpoint)
	_, imdsNetwork, err := net.ParseCIDR(vpc.InstanceMetadataEndpoint)
	if err != nil {
		// This should never happen because we always expect
		// 169.254.169.254/32 to be parsed without any errors.
		log.Errorf("Unable to parse instance metadata endpoint %s", vpc.InstanceMetadataEndpoint)
		return err
	}

	err = netLink.RouteAdd(&netlink.Route{
		Dst:  imdsNetwork,
		Type: syscall.RTN_BLACKHOLE,
	})
	if err != nil {
		log.Errorf("Unable to add route to block instance metadata: %v", err)
		return err
	}

	return nil
}