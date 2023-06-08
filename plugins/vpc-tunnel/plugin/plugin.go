// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
	"github.com/aws/amazon-vpc-cni-plugins/capabilities"
	"github.com/aws/amazon-vpc-cni-plugins/cni"

	cniVersion "github.com/containernetworking/cni/pkg/version"
)

const (
	// pluginName is the name of the plugin as specified in CNI config files.
	pluginName = "vpc-tunnel"

	// logFilePath is the path to the plugin's log file.
	logFilePath = "/var/log/vpc-tunnel.log"
)

var (
	// specVersions is the set of CNI spec versions supported by this plugin.
	specVersions = cniVersion.PluginSupports("0.3.0", "0.3.1", "0.4.0", "1.0.0")
)

// Plugin represents a vpc-tunnel CNI plugin.
type Plugin struct {
	*cni.Plugin
}

// NewPlugin creates a new vpc-tunnel Plugin object.
func NewPlugin() (*Plugin, error) {
	var err error
	plugin := &Plugin{}

	plugin.Plugin, err = cni.NewPlugin(pluginName, specVersions, logFilePath, plugin)
	if err != nil {
		return nil, err
	}

	// Capabilities for vpc-tunnel includes awsvpc-network-mode.
	plugin.Plugin.Capability = capabilities.New(capabilities.TaskENICapability)

	return plugin, nil
}
