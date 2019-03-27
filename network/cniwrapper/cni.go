// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

package cniwrapper

import cniTypes "github.com/containernetworking/cni/pkg/types"

// CNI wraps the method in cni/pkg/types package.
type CNI interface {
	PrintResult(result cniTypes.Result, version string) error
}

type cni struct{
}

// NewCNI creates a new CNI object.
func NewCNI() CNI {
	return &cni{}
}

func (*cni) PrintResult(result cniTypes.Result, version string) error {
	return cniTypes.PrintResult(result, version)
}
