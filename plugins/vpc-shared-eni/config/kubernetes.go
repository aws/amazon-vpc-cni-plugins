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
	"strings"

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
	// namespacePlaceholder is the placeholder string to be replaced with the actual namespace.
	namespacePlaceholder = "{%namespace%}"

	// ignoreUnknown specifies whether unknown CNI arguments are ignored.
	ignoreUnknown = true
)

var (
	retrievePodConfigHandler func(netConfig *NetConfig) error
)

// parseKubernetesArgs parses Kubernetes-specific CNI arguments.
func parseKubernetesArgs(netConfig *NetConfig, args *cniSkel.CmdArgs, isAddCmd bool) error {
	if args == nil || args.Args == "" {
		return nil
	}

	// Parse the arguments in CNI_ARGS environment variable.
	var ka kubernetesArgs
	ka.IgnoreUnknown = ignoreUnknown

	err := cniTypes.LoadArgs(args.Args, &ka)
	if err != nil {
		return fmt.Errorf("failed to parse runtime args: %v", err)
	}

	kc := &netConfig.Kubernetes
	kc.Namespace = string(ka.K8S_POD_NAMESPACE)
	kc.PodName = string(ka.K8S_POD_NAME)
	kc.PodInfraContainerID = string(ka.K8S_POD_INFRA_CONTAINER_ID)

	// The only additional information we need to query from API server is the pod IP address,
	// which is required only for ADD commands. Also the API server may have deleted the pod
	// object already in the DEL path.
	if !isAddCmd {
		return nil
	}

	if kc.Namespace == "" || kc.PodName == "" {
		return fmt.Errorf("missing required args %v", kc)
	}

	// Insert the actual namespace of the pod to the DNS suffix search list.
	for i, suffix := range netConfig.DNS.Search {
		netConfig.DNS.Search[i] = strings.Replace(suffix, namespacePlaceholder, kc.Namespace, 1)
	}

	// Retrieve any missing information not available in netconfig.
	if retrievePodConfigHandler != nil && netConfig.IPAddress == nil {
		err = retrievePodConfigHandler(netConfig)
	}

	return err
}
