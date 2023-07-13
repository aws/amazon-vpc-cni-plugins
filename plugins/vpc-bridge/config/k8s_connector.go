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

//go:build enablek8sconnector && windows

package config

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-bridge/config/k8s"
)

func init() {
	// Define retrievePodConfigHandler when enablek8sconnector tag is set.
	retrievePodConfigHandler = retrievePodConfig
}

// retrievePodConfig retrieves a pod's configuration from an external source.
func retrievePodConfig(netConfig *NetConfig) error {
	kc := netConfig.Kubernetes

	// Creating context with timeout.
	ctx := context.Background()
	ctx, ctxCancel := context.WithTimeout(ctx, time.Minute)
	defer ctxCancel()

	// Retrieve pod IP address CIDR string using k8s connector.
	ipAddress, err := k8s.GetPodIP(ctx, kc.Namespace, kc.PodName)
	if err != nil {
		return fmt.Errorf("failed to get pod IP address %s: %w", kc.PodName, err)
	}

	// Parse IP address returned by k8s binary.
	ipAddr, err := vpc.GetIPAddressFromString(ipAddress)
	if err != nil {
		return fmt.Errorf("invalid IPAddress %s from pod label", ipAddress)
	}
	netConfig.IPAddresses = append(netConfig.IPAddresses, *ipAddr)

	return nil
}
