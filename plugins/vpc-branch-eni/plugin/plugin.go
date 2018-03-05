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

package plugin

import (
	"github.com/aws/amazon-vpc-cni-plugins/cni"

	log "github.com/cihub/seelog"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniVersion "github.com/containernetworking/cni/pkg/version"
)

const (
	// pluginName is the name of the plugin as specified in CNI config files.
	pluginName = "vpc-branch-eni"

	// logFilePath is the path to the plugin's log file.
	logFilePath = "/var/log/vpc-branch-eni.log"
)

// Plugin represents a vpc-branch-eni CNI plugin.
type Plugin struct {
	CNIPlugin *cni.Plugin
}

// NewPlugin creates a new Plugin object.
func NewPlugin() (*Plugin, error) {
	var err error
	plugin := &Plugin{}

	plugin.CNIPlugin, err = cni.NewPlugin(pluginName, logFilePath, plugin)
	if err != nil {
		return nil, err
	}

	return plugin, nil
}

// Initialize initializes the plugin.
func (plugin *Plugin) Initialize() error {
	plugin.CNIPlugin.Initialize()
	return nil
}

// Uninitialize frees the plugin resources.
func (plugin *Plugin) Uninitialize() {
	plugin.CNIPlugin.Uninitialize()
}

// Run starts the plugin.
func (plugin *Plugin) Run() *cniTypes.Error {
	defer log.Flush()

	return plugin.CNIPlugin.Run()
}

// GetVersion returns the CNI plugin information.
func (plugin *Plugin) GetVersion() cniVersion.PluginInfo {
	return GetSpecVersionSupported()
}
