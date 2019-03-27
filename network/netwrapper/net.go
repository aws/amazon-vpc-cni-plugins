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

package netwrapper

import "net"

// Net wraps the methods of net package to be used in testing.
type Net interface {
	// InterfaceByName returns the interface specified by name.
	InterfaceByName(name string) (*net.Interface, error)
	// Interfaces returns a list of the system's network interfaces.
	Interfaces() ([]net.Interface, error)
}

type netImpl struct {
}

// NewNet creates a new Net object.
func NewNet() Net {
	return &netImpl{}
}

func (*netImpl) InterfaceByName(name string) (*net.Interface, error) {
	return net.InterfaceByName(name)
}

func (*netImpl) Interfaces() ([]net.Interface, error) {
	return net.Interfaces()
}