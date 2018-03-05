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
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniVersion "github.com/containernetworking/cni/pkg/version"
)

// API interface abstracts the CNI plugin API described at
// https://github.com/containernetworking/cni/blob/master/SPEC.md
type API interface {
	Add(args *cniSkel.CmdArgs) error
	Del(args *cniSkel.CmdArgs) error
	GetVersion() cniVersion.PluginInfo
}
