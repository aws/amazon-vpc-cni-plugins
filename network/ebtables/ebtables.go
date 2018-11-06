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

// Package ebtables provides simple structured Ethernet bridge frame table administration.
// It is a wrapper around the ebtables user space application, which is the recommended way
// of interacting with the Linux kernel netfilter bridge module.
package ebtables

import (
	"fmt"
	"net"
	"os/exec"

	log "github.com/cihub/seelog"
)

// Table is an Ethernet bridge table.
type Table struct {
	name string
}

// Chain is an ebtables chain.
type Chain string

// Rule is an ebtables rule.
type Rule struct {
	Protocol string
	In       string
	Out      string
	SrcType  string
	Src      net.HardwareAddr
	Dst      net.HardwareAddr
	Match    fmt.Stringer
	Target   fmt.Stringer
}

// ARPMatch is an ebtables ARP match extension.
type ARPMatch struct {
	Op     string
	HType  string
	PType  string
	IPSrc  net.IP
	IPDst  net.IP
	MACSrc net.HardwareAddr
	MACDst net.HardwareAddr
}

// IPv4Match is an ebtables IPv4 match extension.
type IPv4Match struct {
	Src net.IP
	Dst net.IP
}

// DNATTarget is an ebtables DNAT target extension.
type DNATTarget struct {
	ToDst  net.HardwareAddr
	Target StdTarget
}

// SNATTarget is an ebtables SNAT target extension.
type SNATTarget struct {
	ToSrc  net.HardwareAddr
	ARP    bool
	Target StdTarget
}

// StdTarget is an ebtables standard target.
type StdTarget string

const (
	// Name of the ebtables executable.
	ebtablesExe = "ebtables"

	// Built-in ebtables chain names.
	PreRouting  Chain = "PREROUTING"
	Input       Chain = "INPUT"
	Forward     Chain = "FORWARD"
	Output      Chain = "OUTPUT"
	PostRouting Chain = "POSTROUTING"

	// Standard targets.
	Accept   StdTarget = "ACCEPT"
	Drop     StdTarget = "DROP"
	Continue StdTarget = "CONTINUE"
	Return   StdTarget = "RETURN"
)

var (
	// Filter is the Ethernet bridge filter table.
	Filter = Table{name: "filter"}
	// NAT is the Ethernet bridge NAT table.
	NAT = Table{name: "nat"}
	// Broute is the Ethernet bridge broute table.
	Broute = Table{name: "broute"}
)

// String returns the string representation of an ebtables chain.
func (chain *Chain) String() string {
	return string(*chain)
}

// String returns the string representation of an ebtables standard target.
func (stdTarget StdTarget) String() string {
	return "-j " + string(stdTarget)
}

// String returns the string representation of an ebtables rule.
func (rule *Rule) String() string {
	var s string

	if rule.Protocol != "" {
		s += " -p " + rule.Protocol
	}
	if rule.In != "" {
		s += " -i " + rule.In
	}
	if rule.Out != "" {
		s += " -o " + rule.Out
	}
	if rule.SrcType != "" {
		s += " -s " + rule.SrcType
	}
	if rule.Src != nil {
		s += " -s " + rule.Src.String()
	}
	if rule.Dst != nil {
		s += " -d " + rule.Dst.String()
	}
	if rule.Match != nil {
		s += " " + rule.Match.String()
	}
	if rule.Target != nil {
		s += " " + rule.Target.String()
	}

	return s[1:]
}

// String returns the string representation of an ebtables ARP match extension.
func (match *ARPMatch) String() string {
	var s string

	if match.Op != "" {
		s += "--arp-op " + match.Op
	}

	return s
}

// String returns the string representation of an ebtables IPv4 match extension.
func (match *IPv4Match) String() string {
	var s string

	if match.Src != nil {
		s += " --ip-src " + match.Src.String()
	}
	if match.Dst != nil {
		s += " --ip-dst " + match.Dst.String()
	}

	return s[1:]
}

// String returns the string representation of an ebtables DNAT target extension.
func (dnat *DNATTarget) String() string {
	s := "-j dnat"

	if dnat.ToDst != nil {
		s += " --to-dst " + dnat.ToDst.String()
	}
	if dnat.Target != "" {
		s += " --dnat-target " + string(dnat.Target)
	}

	return s
}

// String returns the string representation of an ebtables SNAT target extension.
func (snat *SNATTarget) String() string {
	s := "-j snat"

	if snat.ToSrc != nil {
		s += " --to-src " + snat.ToSrc.String()
	}
	if snat.ARP {
		s += " --snat-arp"
	}
	if snat.Target != "" {
		s += " --snat-target " + string(snat.Target)
	}

	return s
}

// Append appends a rule to the table.
func (table *Table) Append(chain Chain, rule *Rule) error {
	return execute(table.append(chain, rule))
}

// append returns the string representation of an ebtables append command.
func (table *Table) append(chain Chain, rule *Rule) string {
	return table.generateCmd("-A", chain, rule)
}

// Delete deletes a rule from the table.
func (table *Table) Delete(chain Chain, rule *Rule) error {
	return execute(table.delete(chain, rule))
}

// delete returns the string representation of an ebtables delete command.
func (table *Table) delete(chain Chain, rule *Rule) string {
	return table.generateCmd("-D", chain, rule)
}

// generateCmd generates the ebtables command string.
func (table *Table) generateCmd(command string, chain Chain, rule *Rule) string {
	return ebtablesExe + " -t " + table.name + " " + command + " " + chain.String() + " " + rule.String()
}

// execute executes an ebtables command.
func execute(command string) error {
	log.Infof("Executing ebtables command %s.", command)

	cmd := exec.Command("sh", "-c", command)
	err := cmd.Start()
	if err == nil {
		err = cmd.Wait()
	}
	return err
}
