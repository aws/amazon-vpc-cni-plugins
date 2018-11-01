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
	"fmt"
	"math/rand"
	"regexp"
	"time"

	log "github.com/cihub/seelog"
)

const (
	vethLinkNameFormat     = "ve%d-"
	vethLinkPeerNameSuffix = "-2"
	vethLinkRegex          = "^ve(\\d+)-.+-2"

	// maxAllowedIfNameLength is the maximum length allowed for a network
	// device by the linux kernel.
	// https://github.com/torvalds/linux/blob/a9ac6cc47bbb0fdd042012044f737ba13da10cb4/include/uapi/linux/if.h#L33
	maxAllowedIfNameLength = 15
	randIfNameCharset      = "abcdefghijklmnopqrstuvwxyz0123456789"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func generateVethPairNames(branchVlanID int, containerID string, rand bool) (string, string) {
	vethNameWithVlanID := fmt.Sprintf(vethLinkNameFormat, branchVlanID)
	vethName := vethNameWithVlanID + containerID
	vethPeerName := vethName + vethLinkPeerNameSuffix
	if rand || namesExceedAllowedIfNameLength(vethName, vethPeerName) {
		// Either the device length is not within the limits allowed by
		// the kernel or we've been asked to generate rand name
		// explicitly.
		// Override the default name in either case with a randomly
		// generated name.
		vethName = vethNameWithVlanID + randStringBytes(
			maxAllowedIfNameLength-len(vethNameWithVlanID)-len(vethLinkPeerNameSuffix))
		vethPeerName = vethName + vethLinkPeerNameSuffix
	}

	return vethName, vethPeerName
}

func namesExceedAllowedIfNameLength(vethName string, vethPeerName string) bool {
	return len(vethName) > maxAllowedIfNameLength || len(vethPeerName) > maxAllowedIfNameLength
}

func randStringBytes(n int) string {
	b := make([]byte, n)
	randIfNameCharsetLen := len(randIfNameCharset)
	for i := range b {
		b[i] = randIfNameCharset[rand.Intn(randIfNameCharsetLen)]
	}
	return string(b)
}

func vethPeerNameRecognizable(vethPeerName string) bool {
	vethNameRegex, err := regexp.Compile(vethLinkRegex)
	if err != nil {
		log.Errorf("Error compiling veth name %s regex: %v.", vethPeerName, err)
		return false
	}

	return vethNameRegex.MatchString(vethPeerName)
}
