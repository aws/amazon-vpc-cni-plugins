// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
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
	"os"
	"path/filepath"

	"github.com/aws/amazon-vpc-cni-plugins/capabilities"
	"github.com/aws/amazon-vpc-cni-plugins/cni"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-eni/network"

	cniVersion "github.com/containernetworking/cni/pkg/version"
)

const (
	// pluginName is the name of the plugin as specified in CNI config files.
	pluginName = "vpc-eni"
)

var (
	// specVersions is the set of CNI spec versions supported by this plugin.
	specVersions = cniVersion.PluginSupports("0.3.0", "0.3.1", "0.4.0", "1.0.0")
)

// Plugin represents a vpc-eni CNI plugin.
type Plugin struct {
	*cni.Plugin
	nb network.Builder
}

// NewPlugin creates a new Plugin object.
func NewPlugin() (*Plugin, error) {
	var err error
	plugin := &Plugin{}

	plugin.Plugin, err = cni.NewPlugin(pluginName, specVersions, getLogfilePath(), plugin)
	if err != nil {
		return nil, err
	}

	plugin.nb = &network.NetBuilder{}

	// Capabilities for vpc-eni includes awsvpc-network-mode.
	plugin.Capability = capabilities.New(capabilities.TaskENICapability)

	return plugin, nil
}

// getLogfilePath returns the path of the log file.
func getLogfilePath() string {
	programData, ok := os.LookupEnv("ProgramData")
	if !ok {
		programData = `C:\ProgramData`
	}

	return filepath.Join(programData, `Amazon\ECS\log\cni\vpc-eni.log`)
}
