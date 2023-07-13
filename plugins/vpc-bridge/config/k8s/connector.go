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

package k8s

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"

	log "github.com/cihub/seelog"
)

const (
	// Represents Env variable for k8s connector binary path.
	envK8sConnectorBinaryPath = "AWS_VPC_CNI_K8S_CONNECTOR_BINARY_PATH"
	// Represents default path for k8s connector binary in EKS Windows AMIs.
	defaultK8sConnectorBinaryPath = `C:\Program Files\Amazon\EKS\bin\aws-vpc-cni-k8s-connector.exe`

	// Represents Env for log level for k8s connector binary.
	envLogLevel = "VPC_CNI_LOG_LEVEL"
	// Represents default log level for k8s connector binary.
	defaultLogLevel = "info"
)

// GetPodIP retrieves pod IP address using k8s connector binary.
// Output from binary is received over named pipe.
// Create and read operations on named pipe are handled in separate go routine.
// Named pipe path will be passed as argument to k8s connector binary execution.
func GetPodIP(ctx context.Context, podNamespace, podName string) (string, error) {
	// Get new named pipe path.
	pipeName, err := newPipe()
	if err != nil {
		return "", fmt.Errorf("error creating new pipe: %w", err)
	}

	resultChan := make(chan pipeReadResult)

	// Read output from named pipe in separate go routine as accepting and reading connection is blocking operation.
	go readResultFromPipe(ctx, pipeName, resultChan)

	// Executing k8s connector binary in main routine. binary will write output to named pipe.
	err = executeK8sConnector(ctx, podNamespace, podName, pipeName)
	if err != nil {
		return "", fmt.Errorf("error executing k8s connector: %w", err)
	}

	// Get output from named pipe using result chan.
	var result pipeReadResult
	select {
	// Check if context timed out.
	case <-ctx.Done():
		return "", fmt.Errorf("error getting output from pipe: %w", ctx.Err())
	case result = <-resultChan:
	}

	if result.error != nil {
		return "", fmt.Errorf("error reading output from pipe: %w", result.error)
	}

	log.Debugf("Got pod IP address %s for pod %s in namespace %s", result.output, podName, podNamespace)
	return result.output, nil
}

// executeK8sConnector executes aws-vpc-cni-k8s-connector binary to get pod IP address.
// Output from binary is received over named pipe. Execution logs from binary are returned over stdout.
func executeK8sConnector(ctx context.Context, podNamespace string, podName string, pipe string) error {
	// Prepare command to execute binary with required args.
	cmd := exec.CommandContext(ctx, getK8sConnectorBinaryPath(),
		"-pod-name", podName, "-pod-namespace", podNamespace,
		"-pipe", pipe, "-log-level", getK8sConnectorLogLevel())
	log.Debugf("Executing cmd %s to get pod IP address", cmd.String())

	// Setting Stderr for command to receive complete error.
	var errBytes bytes.Buffer
	cmd.Stderr = &errBytes

	output, err := cmd.Output()

	log.Infof("Logs from k8s connector binary...\n")
	log.Infof("%s\n", string(output))
	log.Infof("End of k8s connector binary logs\n")

	if err != nil {
		return fmt.Errorf("error executing connector binary: %w with execution error: %s", err, errBytes.String())
	}

	return nil
}

// getK8sConnectorBinaryPath returns path to k8s connector binary.
func getK8sConnectorBinaryPath() string {
	connectorBinaryPath := os.Getenv(envK8sConnectorBinaryPath)
	if connectorBinaryPath == "" {
		connectorBinaryPath = defaultK8sConnectorBinaryPath
	}
	return connectorBinaryPath
}

// getK8sConnectorLogLevel returns the log level for k8s connector binary.
func getK8sConnectorLogLevel() string {
	logLevel := os.Getenv(envLogLevel)
	if logLevel == "" {
		logLevel = defaultLogLevel
	}
	return logLevel
}
