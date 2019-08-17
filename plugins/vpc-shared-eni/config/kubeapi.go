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

// +build !disablekubeapi

package config

import (
	"fmt"
	"os"
	"time"

	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"

	log "github.com/cihub/seelog"

	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// vpcResourceNameIPv4Address is the extended resource name for VPC private IPv4 addresses.
	vpcResourceNameIPv4Address = "vpc.amazonaws.com/PrivateIPv4Address"

	// The number of retries and delay for Kubernetes API calls.
	retries    = 20
	retryDelay = 100 * time.Millisecond
)

func init() {
	retrievePodConfigHandler = retrievePodConfig
}

// retrievePodConfig retrieves a pod's configuration from an external source.
func retrievePodConfig(netConfig *NetConfig) error {
	// Retrieve the IP address configuration from pod.
	kubeClient, err := createKubeClient()
	if err != nil {
		return err
	}

	var ipAddress string
	kc := &netConfig.Kubernetes

	// Wait until the pod is annotated with an IP address resource label.
	for i := 0; i < retries; i++ {
		pod, err := kubeClient.CoreV1().Pods(kc.Namespace).Get(kc.PodName, metaV1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get pod %s: %v", kc.PodName, err)
		}

		podAnnotations := pod.GetAnnotations()
		ipAddress, _ = podAnnotations[vpcResourceNameIPv4Address]
		if ipAddress != "" {
			break
		}

		log.Infof("Waiting for pod label %s.", vpcResourceNameIPv4Address)
		time.Sleep(retryDelay)
	}

	if ipAddress == "" {
		return fmt.Errorf("pod does not have label %s", vpcResourceNameIPv4Address)
	}

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
