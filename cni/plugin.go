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

package cni

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strconv"

	"github.com/aws/amazon-vpc-cni-plugins/capabilities"
	"github.com/aws/amazon-vpc-cni-plugins/logger"
	"github.com/aws/amazon-vpc-cni-plugins/version"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniVersion "github.com/containernetworking/cni/pkg/version"
)

// Plugin is the base class to all CNI plugins.
type Plugin struct {
	Name         string
	SpecVersions cniVersion.PluginInfo
	LogFilePath  string
	Commands     API
	Capability   *capabilities.Capability
}

// NewPlugin creates a new CNI Plugin object.
func NewPlugin(
	name string,
	specVersions cniVersion.PluginInfo,
	logFilePath string,
	cmds API) (*Plugin, error) {

	return &Plugin{
		Name:         name,
		SpecVersions: specVersions,
		LogFilePath:  logFilePath,
		Commands:     cmds,
		Capability:   capabilities.New(),
	}, nil
}

// Initialize initializes the CNI plugin.
func (plugin *Plugin) Initialize() error {
	// Configure logging.
	logger.Setup(plugin.LogFilePath)

	return nil
}

// Uninitialize frees the resources in the CNI plugin.
func (plugin *Plugin) Uninitialize() {
}

// Run starts the CNI plugin.
func (plugin *Plugin) Run() *cniTypes.Error {
	defer log.Flush()

	// Parse command line arguments.
	var printVersion, printCapabilities bool
	flag.BoolVar(&printVersion, version.Command, false, "prints version and exits")
	flag.BoolVar(&printCapabilities, capabilities.Command, false, "prints capabilities and exits")
	flag.Parse()

	if printVersion {
		err := plugin.printVersionInfo()
		if err != nil {
			os.Stderr.WriteString(fmt.Sprintf("Failed to print version: %v", err))
			return nil
		}
		return nil
	}

	if printCapabilities {
		err := plugin.Capability.Print()
		if err != nil {
			os.Stderr.WriteString(fmt.Sprintf("Failed to print capabilities: %v", err))
			return nil
		}
		return nil
	}

	// Ensure that goroutines do not change OS threads during namespace operations.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Recover from panics.
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 1<<12)
			len := runtime.Stack(buf, false)

			cniErr := &cniTypes.Error{
				Code:    100,
				Msg:     fmt.Sprintf("%v", r),
				Details: string(buf[:len]),
			}
			cniErr.Print()

			log.Errorf("Recovered panic: %v %v\n", cniErr.Msg, cniErr.Details)
		}
	}()

	log.Infof("Plugin %s version %s executing CNI command.", plugin.Name, version.Version)

	// Execute CNI command handlers.
	cniErr := cniSkel.PluginMainWithError(
		plugin.Commands.Add, plugin.Commands.Del, plugin.Commands.GetVersion())
	if cniErr != nil {
		log.Errorf("CNI command failed: %+v", cniErr)
	}

	return cniErr
}

// Add is an empty CNI ADD command handler to ensure all CNI plugins implement CNIAPI.
func (plugin *Plugin) Add(args *cniSkel.CmdArgs) error {
	return nil
}

// Del is an empty CNI DEL command handler to ensure all CNI plugins implement CNIAPI.
func (plugin *Plugin) Del(args *cniSkel.CmdArgs) error {
	return nil
}

// GetVersion is the default CNI VERSION command handler.
func (plugin *Plugin) GetVersion() cniVersion.PluginInfo {
	return plugin.SpecVersions
}

// printVersionInfo prints the plugin version.
func (plugin *Plugin) printVersionInfo() error {
	versionInfo, err := version.String()
	if err != nil {
		return err
	}

	fmt.Println(versionInfo)

	return nil
}

// LookupUser returns the UID for the given username, or the current user.
func (plugin *Plugin) LookupUser(userName string) (int, error) {
	var u *user.User
	var err error

	// Lookup the current user if no username is given.
	if userName == "" {
		u, err = user.Current()
	} else {
		u, err = user.Lookup(userName)
	}

	if err != nil {
		return -1, err
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1, err
	}

	return uid, nil
}
