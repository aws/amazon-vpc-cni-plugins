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

package ipcfg

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"strconv"
)

const (
	ipv4Forwarding = "/proc/sys/net/ipv4/conf/%s/forwarding"
	ipv4ProxyARP   = "/proc/sys/net/ipv4/conf/%s/proxy_arp"

	ipv6Forwarding = "/proc/sys/net/ipv6/conf/%s/forwarding"
	ipv6AcceptRA   = "/proc/sys/net/ipv6/conf/%s/accept_ra"
	ipv6AcceptDAD  = "/proc/sys/net/ipv6/conf/%s/accept_dad"
)

// SetIPv4Forwarding sets the IPv4 forwarding property of an interface to the given value.
func SetIPv4Forwarding(ifName string, value int) error {
	return set(fmt.Sprintf(ipv4Forwarding, ifName), value)
}

// SetIPv4ProxyARP sets the IPv4 proxy ARP property of an interface to the given value.
func SetIPv4ProxyARP(ifName string, value int) error {
	return set(fmt.Sprintf(ipv4ProxyARP, ifName), value)
}

// SetIPv6Forwarding sets the IPv6 forwarding property of an interface to the given value.
func SetIPv6Forwarding(ifName string, value int) error {
	return set(fmt.Sprintf(ipv6Forwarding, ifName), value)
}

// SetIPv6AcceptRA sets the IPv6 accept RA property of an interface to the given value.
func SetIPv6AcceptRA(ifName string, value int) error {
	return set(fmt.Sprintf(ipv6AcceptRA, ifName), value)
}

// SetIPv6AcceptDAD sets the IPv6 accept DAD property of an interface to the given value.
func SetIPv6AcceptDAD(ifName string, value int) error {
	return set(fmt.Sprintf(ipv6AcceptDAD, ifName), value)
}

// Set sets a system variable to the given value.
func set(name string, value int) error {
	valueStr := strconv.Itoa(value)

	// Do not rewrite if the value is already set.
	currValue, err := ioutil.ReadFile(name)
	if err == nil && bytes.Equal(bytes.TrimSpace(currValue), []byte(valueStr)) {
		return nil
	}

	return ioutil.WriteFile(name, []byte(valueStr), 0644)
}
