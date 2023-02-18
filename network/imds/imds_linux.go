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

	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"

	log "github.com/cihub/seelog"
	"github.com/vishvananda/netlink"
)

// BlockInstanceMetadataEndpoint adds a blackhole rule for IMDS endpoint.
func BlockInstanceMetadataEndpoint() error {
	for _, ep := range vpc.InstanceMetadataEndpoints {
		log.Infof("Adding route to block instance metadata endpoint %s", ep)
		_, imdsNetwork, err := net.ParseCIDR(ep)
		if err != nil {
			// This should never happen as these IP addresses are hardcoded.
			log.Errorf("Unable to parse instance metadata endpoint %s", ep)
			return err
		}

		err = netlink.RouteAdd(&netlink.Route{
			Dst:  imdsNetwork,
			Type: syscall.RTN_BLACKHOLE,
		})
		if err != nil {
			log.Errorf("Unable to add route to block instance metadata: %v", err)
			return err
		}
	}
	return nil
}
