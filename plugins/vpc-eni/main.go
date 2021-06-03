// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package main

import (
	"os"

	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-eni/plugin"
)

// main is the entry point for vpc-eni plugin executable.
func main() {
	plugin, err := plugin.NewPlugin()
	if err != nil {
		os.Exit(1)
	}

	err = plugin.Initialize()
	if err != nil {
		os.Exit(1)
	}

	cniErr := plugin.Run()
	if cniErr != nil {
		cniErr.Print()
		os.Exit(1)
	}
}
