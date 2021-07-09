// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package imds

import (
	"encoding/json"

	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"

	"github.com/Microsoft/hcsshim"
	log "github.com/cihub/seelog"
)

const (
	// hnsAclPolicyAllProtocols represents all the protocols.
	hnsAclPolicyAllProtocols = 256
	// hnsAclPolicyHighPriority represents the higher priority number.
	hnsAclPolicyHighPriority = 200
	// hnsAclPolicyLowPriority represents the lower priority number.
	hnsAclPolicyLowPriority = 300
)

// BlockInstanceMetadataEndpoint blocks the IMDS endpoint for Windows by creating HNS ACLs.
func BlockInstanceMetadataEndpoint(hnsEndpoint *hcsshim.HNSEndpoint) error {
	log.Infof("Adding ACLs to block instance metadata endpoint %s", vpc.InstanceMetadataEndpoint)
	// Create an ACL policy to block traffic to instance metadata endpoint.
	err := addEndpointPolicy(
		hnsEndpoint,
		hcsshim.ACLPolicy{
			Type:            hcsshim.ACL,
			Action:          hcsshim.Block,
			Direction:       hcsshim.Out,
			RemoteAddresses: vpc.InstanceMetadataEndpoint,
			Protocol:        hnsAclPolicyAllProtocols,
			Priority:        hnsAclPolicyHighPriority,
		})
	if err != nil {
		log.Errorf("Failed to add endpoint ACL policy to block imds traffic: %v.", err)
		return err
	}

	// Create an ACL policy to allow all incoming traffic.
	err = addEndpointPolicy(
		hnsEndpoint,
		hcsshim.ACLPolicy{
			Type:      hcsshim.ACL,
			Action:    hcsshim.Allow,
			Direction: hcsshim.In,
			Protocol:  hnsAclPolicyAllProtocols,
			Priority:  hnsAclPolicyLowPriority,
		})
	if err != nil {
		log.Errorf("Failed to add endpoint ACL policy to allow incoming traffic: %v.", err)
		return err
	}

	// Create an ACL policy to allow all outgoing traffic.
	// The priority of this policy should be lower than that of the block policy for disabling IMDS.
	err = addEndpointPolicy(
		hnsEndpoint,
		hcsshim.ACLPolicy{
			Type:      hcsshim.ACL,
			Action:    hcsshim.Allow,
			Direction: hcsshim.Out,
			Protocol:  hnsAclPolicyAllProtocols,
			Priority:  hnsAclPolicyLowPriority,
		})
	if err != nil {
		log.Errorf("Failed to add endpoint ACL policy to allow outgoing traffic: %v.", err)
		return err
	}

	return nil
}

// addEndpointPolicy adds a policy to an HNS endpoint.
func addEndpointPolicy(ep *hcsshim.HNSEndpoint, policy interface{}) error {
	buf, err := json.Marshal(policy)
	if err != nil {
		log.Errorf("Failed to encode policy: %v.", err)
		return err
	}

	ep.Policies = append(ep.Policies, buf)

	return nil
}
