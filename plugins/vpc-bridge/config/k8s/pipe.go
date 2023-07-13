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

//go:build enablek8sconnector && windows

package k8s

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	winio "github.com/Microsoft/go-winio"
	log "github.com/cihub/seelog"
	"golang.org/x/sys/windows"
)

const (
	// PipeConnectionTimeout Represents default timeout for reading from connection object.
	PipeConnectionTimeout = 1 * time.Minute

	// NamedPipePathPrefix Represents prefix for named pipe path.
	NamedPipePathPrefix = `\\.\pipe\ProtectedPrefix\Administrators\aws-vpc-k8s-connector`
)

// pipeReadResult Represents message for communication between main and go routine which reads output from named pipe.
type pipeReadResult struct {
	output string // Represents output from named pipe.
	error  error  // Represents error while reading output.
}

// newPipe Create new random named pipe path.
func newPipe() (string, error) {
	// Generate GUID random string.
	g, err := windows.GenerateGUID()
	if err != nil {
		return "", fmt.Errorf("error creating unique name for named pipe: %w", err)
	}
	// Create pipe path with prefix.
	pipeName := fmt.Sprintf("%s-%s", NamedPipePathPrefix, g.String())
	return pipeName, nil
}

// readResultFromPipe func executes in separate go routine as it has blocking operations.
// It creates listener and start accepting connections on named pipe. Read output from conn object.
// Pass output from named pipe to main routine via chan passed as argument. Write any error to same result chan.
// Func closes result channel, pipe listener, conn object.
func readResultFromPipe(ctx context.Context, pipeName string, result chan pipeReadResult) {
	// Defer closing channel from sender go routine.
	// We can't close in receiver as sender go routine will panic trying to send on closed channel.
	defer close(result)

	// Create pipe and get listener.
	pipeListener, err := winio.ListenPipe(pipeName, nil)
	if err != nil {
		log.Errorf("Error creating named pipe %s: %w", pipeName, err)
		result <- pipeReadResult{error: fmt.Errorf("error creating named pipe %s: %w", pipeName, err)}
		return
	}
	defer pipeListener.Close()
	log.Debugf("Named piped %s created", pipeName)

	// Accept connection on named pipe. This operation is blocked until client(k8s connector binary) dials into pipe.
	conn, err := pipeListener.Accept()
	if err != nil {
		log.Errorf("Error accepting connection on pipe listener %v: %w", pipeName, err)
		result <- pipeReadResult{error: fmt.Errorf("error accepting connection on pipe listener %v: %w", pipeName, err)}
		return
	}
	defer conn.Close()

	// Get deadline from context, use it to set deadline for conn.
	contextDeadline, ok := ctx.Deadline()
	if !ok {
		log.Debugf("Using default timeout %s for pipe connection", PipeConnectionTimeout)
		contextDeadline = time.Now().Add(PipeConnectionTimeout)
	}
	// Setup read timeout on conn object.
	err = conn.SetReadDeadline(contextDeadline)
	if err != nil {
		log.Errorf("Error setting timeout for pipe connection %v: %w", pipeName, err)
		result <- pipeReadResult{error: fmt.Errorf("error setting timeout for pipe connection %v: %w", pipeName, err)}
		return
	}

	// Get output from named pipe. This operation is blocking until client(k8s connector binary) has written output.
	// Returns error if output is not available within above given timeout.
	var output bytes.Buffer
	_, err = io.Copy(&output, conn) // Copy output from pipe connection to buffer.
	if err != nil {
		log.Errorf("Error reading from named piped %v: %w", pipeName, err)
		result <- pipeReadResult{error: fmt.Errorf("error reading from named piped %v: %w", pipeName, err)}
		return
	}

	// Send output from named pipe on channel.
	result <- pipeReadResult{output: output.String()}
	return
}
