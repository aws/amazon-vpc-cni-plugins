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
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"

	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/aws/amazon-vpc-cni-plugins/version"
)

// netnsexec netnsNameOrPath cmd [arg]...
func main() {
	// Parse arguments.
	var printVersion bool
	flag.BoolVar(&printVersion, version.Command, false, "prints version and exits")
	flag.Parse()

	if printVersion {
		versionInfo, _ := version.String()
		fmt.Println(versionInfo)
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) < 2 {
		fmt.Println("netnsexec netnsNameOrPath cmd [arg]...")
		os.Exit(0)
	}

	nsName := args[0]
	cmdName := args[1]

	// Ensure that goroutines do not change OS threads during namespace operations.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	ns, err := netns.GetNetNS(nsName)
	if err != nil {
		fmt.Printf("Failed to find netns %s: %v.\n", nsName, err)
		os.Exit(1)
	}

	err = ns.Run(func() error {
		cmd := exec.Command(cmdName, args[2:]...)

		var errStdout, errStderr error
		cmdStdout, _ := cmd.StdoutPipe()
		cmdStderr, _ := cmd.StderrPipe()

		err := cmd.Start()
		if err != nil {
			return fmt.Errorf("cmd.Start() failed: %v", err)
		}

		// Redirect cmd's stdout and stderr.
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			_, errStdout = io.Copy(os.Stdout, cmdStdout)
			wg.Done()
		}()

		_, errStderr = io.Copy(os.Stderr, cmdStderr)
		wg.Wait()

		err = cmd.Wait()

		if err != nil {
			return fmt.Errorf("cmd.Wait() failed: %v", err)
		}

		if errStdout != nil || errStderr != nil {
			return fmt.Errorf("failed to capture stdout: %v or stderr: %v", errStdout, errStderr)
		}

		return err
	})

	if err != nil {
		fmt.Printf("Failed to run command %s: %v.\n", cmdName, err)
		os.Exit(1)
	}
}
