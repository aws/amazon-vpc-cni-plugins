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

package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
)

// netnsexec netnsNameOrPath cmd [arg]...
func main() {
	var output []byte

	flag.Parse()
	args := flag.Args()
	nsName := args[0]
	cmd := args[1]

	// Ensure that goroutines do not change OS threads during namespace operations.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ns, err := netns.GetNetNS(nsName)
	if err != nil {
		fmt.Printf("Failed to find netns %s: %v.\n", nsName, err)
		os.Exit(1)
	}

	err = ns.Run(func() error {
		var err error
		output, err = exec.Command(cmd, args[2:]...).Output()
		return err
	})

	if err != nil {
		fmt.Printf("Failed to run command %v: %v.\n", cmd, err)
		os.Exit(1)
	}

	fmt.Printf("%v", string(output))
}
