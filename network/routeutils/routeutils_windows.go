// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package routeutils

import (
	"errors"
	"net"
	"os/exec"

	log "github.com/cihub/seelog"
)

const (
	routeCommand          = "route"
	routeAddCommand       = "add"
	routeDeleteCommand    = "delete"
	routeCommandMask      = "mask"
	routeCommandInterface = "if"
)

type routeUtils struct{}

// New returns a new network utils
func New() RouteUtils {
	return &routeUtils{}
}

// AddRoute adds a route entry in the routing table
func (utils *routeUtils) AddRoute(destination *net.IP, subnetMask *net.IP, gateway *net.IP, interfaceNum *int) error {
	if destination == nil || subnetMask == nil || gateway == nil {
		return errors.New("unable to delete route due to invalid arguments")
	}

	commandArgs := utils.generateCommandArgs(destination, subnetMask, gateway, interfaceNum)
	log.Infof("Executing command: %v", commandArgs)

	return exec.Command(routeAddCommand, commandArgs...).Run()
}

// DeleteRoute deletes a route entry from the routing table
func (utils *routeUtils) DeleteRoute(destination *net.IP, subnetMask *net.IP, gateway *net.IP) error {
	if destination == nil || subnetMask == nil {
		return errors.New("unable to delete route due to invalid arguments")
	}

	commandArgs := utils.generateCommandArgs(destination, subnetMask, gateway, nil)
	log.Infof("Executing command: %v", commandArgs)

	return exec.Command(routeCommand, commandArgs...).Run()
}

// generateCommandArgs generates the command arguments based on the input provided
func (utils *routeUtils) generateCommandArgs(destination *net.IP, subnetMask *net.IP, gateway *net.IP, interfaceNum *int) []string {
	commandArgs := make([]string, 4, 6)

	commandArgs[0] = routeDeleteCommand
	commandArgs[1] = destination.String()
	commandArgs[2] = routeCommandMask
	commandArgs[3] = subnetMask.String()
	if gateway != nil {
		commandArgs = append(commandArgs, gateway.String())
	}
	if interfaceNum != nil {
		commandArgs = append(commandArgs, routeCommandInterface)
		commandArgs = append(commandArgs, string(*interfaceNum))
	}

	return commandArgs
}
