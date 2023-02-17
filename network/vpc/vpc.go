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

package vpc

const (
	// JumboFrameMTU is the VPC jumbo Ethernet frame Maximum Transmission Unit size in bytes.
	JumboFrameMTU = 9001
)

var (
	// InstanceMetadataEndpoints is the list of EC2 instance metadata endpoints.
	InstanceMetadataEndpoints = []string{"169.254.169.254/32", "fd00:ec2::254/128"}
)
