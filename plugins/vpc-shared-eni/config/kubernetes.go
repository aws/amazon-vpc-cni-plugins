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

package config

import (
	"fmt"

	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
)

// kubernetesArgs defines the Kubernetes arguments passed in CNI_ARGS environment variable.
type kubernetesArgs struct {
	cniTypes.CommonArgs
	K8S_POD_NAMESPACE          cniTypes.UnmarshallableString
	K8S_POD_NAME               cniTypes.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID cniTypes.UnmarshallableString
}

// KubernetesConfig contains Kubernetes-specific configuration.
type KubernetesConfig struct {
	Namespace           string
	PodName             string
	PodInfraContainerID string
	ServiceCIDR         string
}

const (
	// ignoreUnknown specifies whether unknown CNI arguments are ignored.
	ignoreUnknown = true
)

// parseKubernetesArgs parses Kubernetes-specific CNI arguments.
func parseKubernetesArgs(netConfig *NetConfig, args *cniSkel.CmdArgs) error {
	if args == nil || args.Args == "" {
		return nil
	}

	var ka kubernetesArgs
	ka.IgnoreUnknown = ignoreUnknown

	if err := cniTypes.LoadArgs(args.Args, &ka); err != nil {
		return fmt.Errorf("failed to parse runtime args: %v", err)
	}

	kc := &netConfig.Kubernetes
	kc.Namespace = string(ka.K8S_POD_NAMESPACE)
	kc.PodName = string(ka.K8S_POD_NAME)
	kc.PodInfraContainerID = string(ka.K8S_POD_INFRA_CONTAINER_ID)

	return nil
}
