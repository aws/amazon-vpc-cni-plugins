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
	"os"
	"time"

	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"

	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
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
	// vpcResourceNameIPAddress is the extended resource name for VPC private IP addresses.
	vpcResourceNameIPAddress = "vpc.amazonaws.com/PrivateIPv4Address"

	// The number of retries and delay for Kubernetes API calls.
	retries    = 20
	retryDelay = 100 * time.Millisecond

	// ignoreUnknown specifies whether unknown CNI arguments are ignored.
	ignoreUnknown = true
)

var (
	k8sClient kubernetes.Interface
)

// parseKubernetesArgs parses Kubernetes-specific CNI arguments.
func parseKubernetesArgs(netConfig *NetConfig, args *cniSkel.CmdArgs) error {
	if args == nil || args.Args == "" {
		return nil
	}

	// Parse the arguments in CNI_ARGS environment variable.
	var ka kubernetesArgs
	ka.IgnoreUnknown = ignoreUnknown

	if err := cniTypes.LoadArgs(args.Args, &ka); err != nil {
		return fmt.Errorf("failed to parse runtime args: %v", err)
	}

	kc := &netConfig.Kubernetes
	kc.Namespace = string(ka.K8S_POD_NAMESPACE)
	kc.PodName = string(ka.K8S_POD_NAME)
	kc.PodInfraContainerID = string(ka.K8S_POD_INFRA_CONTAINER_ID)

	if kc.Namespace == "" || kc.PodName == "" {
		return fmt.Errorf("missing required args %v", kc)
	}

	// Retrieve the IP address configuration from pod.
	k8sClient, err := createKubeClient()
	if err != nil {
		return err
	}

	var ipAddress string

	// Wait until the pod is annotated with an IP address resource label.
	for i := 0; i < retries; i++ {
		pod, err := k8sClient.CoreV1().Pods(kc.Namespace).Get(kc.PodName, metaV1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get pod %s: %v", kc.PodName, err)
		}

		podLabels := pod.GetLabels()
		ipAddress, _ = podLabels[vpcResourceNameIPAddress]
		if ipAddress != "" {
			break
		}

		log.Info("Waiting for pod label %s.", vpcResourceNameIPAddress)
		time.Sleep(retryDelay)
	}

	if ipAddress == "" {
		return fmt.Errorf("pod does not have label %s", vpcResourceNameIPAddress)
	}

	// Get the subnet prefix length from ENI IP address.
	prefixLength, _ := netConfig.ENIIPAddress.Mask.Size()
	ipAddress = fmt.Sprintf("%s/%d", ipAddress, prefixLength)

	netConfig.IPAddress, err = vpc.GetIPAddressFromString(ipAddress)
	if err != nil {
		return fmt.Errorf("invalid IPAddress %s from pod label", ipAddress)
	}

	return nil
}

// createKubeClient creates a Kubernetes client.
func createKubeClient() (kubernetes.Interface, error) {
	// Set default kubeconfig.
	kubeconfig := os.Getenv("KUBECONFIG")

	// Create the config from the path.
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build kubeconfig: %v", err)
	}

	// Generate the client for the given config.
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %v", err)
	}

	return client, nil
}
