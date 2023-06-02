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

package vpc

import (
	"fmt"
	"strings"
)

const (
	// protocolTCP indicates TCP protocol number for port mapping.
	protocolTCP uint32 = 6
	// protocolUDP indicates UDP protocol number for port mapping.
	protocolUDP uint32 = 17
)

// ProtocolToNumber converts the protocol to it's assigned number.
// Reference: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
func ProtocolToNumber(protocol string) (uint32, error) {
	var protocolNumber uint32
	switch strings.ToUpper(protocol) {
	case "TCP":
		protocolNumber = protocolTCP
	case "UDP":
		protocolNumber = protocolUDP
	default:
		// Protocol number 256 is invalid and therefore, returned with the error.
		return 256, fmt.Errorf("unsupported protocol for portmapping: %s", protocol)
	}

	return protocolNumber, nil
}
