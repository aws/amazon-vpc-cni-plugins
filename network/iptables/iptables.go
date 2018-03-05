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

package iptables

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
)

const (
	// Name of the iptables restore command.
	restoreCmd = "iptables-restore"

	// Well-known iptables table names.
	filter = "filter"
	nat    = "nat"
	mangle = "mangle"

	// Built-in iptables chain names.
	input       = "INPUT"
	forward     = "FORWARD"
	output      = "OUTPUT"
	prerouting  = "PREROUTING"
	postrouting = "POSTROUTING"

	// Default chain policy.
	defaultPolicy = "ACCEPT"
)

// Session represents an iptables session.
type Session struct {
	restorePath string
	Filter      *Table
	Nat         *Table
	Mangle      *Table
}

// Table represents an iptables table.
type Table struct {
	name        string
	Input       *Chain
	Forward     *Chain
	Output      *Chain
	Prerouting  *Chain
	Postrouting *Chain
	Chains      map[string]*Chain
}

// Chain represents an iptables chain, which contains an ordered set of rules.
type Chain struct {
	name   string
	policy string
	rules  []string
}

// Rule represents an iptables rule.
type Rule struct {
	cmd  string
	args []string
}

// NewSession creates a new Session object.
func NewSession() (*Session, error) {
	restorePath, err := exec.LookPath(restoreCmd)
	if err != nil {
		return nil, err
	}

	session := &Session{
		restorePath: restorePath,
		Filter: &Table{
			name:   filter,
			Chains: make(map[string]*Chain),
		},
		Nat: &Table{
			name:   nat,
			Chains: make(map[string]*Chain),
		},
		Mangle: &Table{
			name:   mangle,
			Chains: make(map[string]*Chain),
		},
	}

	session.Filter.Input, _ = NewChain(input)
	session.Filter.Forward, _ = NewChain(forward)
	session.Filter.Output, _ = NewChain(output)
	session.Filter.Chains[input] = session.Filter.Input
	session.Filter.Chains[forward] = session.Filter.Forward
	session.Filter.Chains[output] = session.Filter.Output

	session.Nat.Prerouting, _ = NewChain(prerouting)
	session.Nat.Input, _ = NewChain(input)
	session.Nat.Output, _ = NewChain(output)
	session.Nat.Postrouting, _ = NewChain(postrouting)
	session.Nat.Chains[prerouting] = session.Nat.Prerouting
	session.Nat.Chains[input] = session.Nat.Input
	session.Nat.Chains[output] = session.Nat.Output
	session.Nat.Chains[postrouting] = session.Nat.Postrouting

	session.Mangle.Prerouting, _ = NewChain(prerouting)
	session.Mangle.Input, _ = NewChain(input)
	session.Mangle.Forward, _ = NewChain(forward)
	session.Mangle.Output, _ = NewChain(output)
	session.Mangle.Postrouting, _ = NewChain(postrouting)
	session.Mangle.Chains[prerouting] = session.Mangle.Prerouting
	session.Mangle.Chains[input] = session.Mangle.Input
	session.Mangle.Chains[forward] = session.Mangle.Forward
	session.Mangle.Chains[output] = session.Mangle.Output
	session.Mangle.Chains[postrouting] = session.Mangle.Postrouting

	return session, nil
}

// Serialize converts the session state to a string in iptables-restore format.
func (s *Session) Serialize() string {
	var str string

	for _, tv := range []*Table{s.Filter, s.Nat, s.Mangle} {
		str += fmt.Sprintf("*%s\n", tv.name)
		for _, cv := range tv.Chains {
			if cv != nil {
				str += fmt.Sprintf(":%s %s [0:0]\n", cv.name, cv.policy)
			}
		}
		for _, cv := range tv.Chains {
			if cv != nil {
				if cv.rules != nil {
					for _, rv := range cv.rules {
						str += rv + "\n"
					}
				}
			}
		}
		str += fmt.Sprintf("COMMIT\n")
	}

	return str
}

// Commit loads all rules in this session atomically to iptables.
func (s *Session) Commit(stdout io.Writer) error {
	var stderr bytes.Buffer

	// Pass the serialized session state via stdin.
	cmd := exec.Cmd{
		Path:   s.restorePath,
		Args:   nil,
		Stdin:  bytes.NewBufferString(s.Serialize()),
		Stdout: stdout,
		Stderr: &stderr,
	}

	// Execute the restore command.
	if err := cmd.Run(); err != nil {
		switch e := err.(type) {
		case *exec.ExitError:
			return fmt.Errorf("%v %v %v", *e, cmd, stderr.String())
		default:
			return err
		}
	}

	return nil
}

// NewChain creates a new Chain object.
func NewChain(name string) (*Chain, error) {
	chain := &Chain{
		name:   name,
		policy: defaultPolicy,
	}

	return chain, nil
}

// Append appends a rule to the chain.
func (chain *Chain) Append(rule string) {
	rule = fmt.Sprintf("-A %s %s", chain.name, rule)
	chain.rules = append(chain.rules, rule)
}

// Appendf appends a rule with variadic arguments to the chain.
func (chain *Chain) Appendf(rule string, args ...interface{}) {
	rule = fmt.Sprintf(rule, args...)
	rule = fmt.Sprintf("-A %s %s", chain.name, rule)
	chain.rules = append(chain.rules, rule)
}
