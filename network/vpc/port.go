// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package vpc

import (
	"fmt"
	"strconv"
	"strings"
)

// PortMapping contains the container port to host port mapping information.
type PortMapping struct {
	Protocol      string `json:"protocol"`
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
}

// ValidatePort checks whether the port only has digits and is within valid port range.
func ValidatePort(p string) error {
	port := strings.TrimSpace(p)

	if t, err := strconv.ParseUint(port, 10, 16); err != nil || t == 0 {
		return fmt.Errorf("invalid port %s specified", p)
	}
	return nil
}

// ValidatePortRange checks whether the given port is within valid port range.
func ValidatePortRange(port int) error {
	if port > 0 && port <= 65535 {
		return nil
	}
	return fmt.Errorf("invalid port %d specified", port)
}
