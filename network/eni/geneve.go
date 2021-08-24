// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

// +build linux

package eni

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"

	log "github.com/cihub/seelog"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
)

// DeviceBusyErrMsg is the error message we get while adding a new GENEVE
// interface that has destination IP, port and VNI that conflicts with an existing one.
const DeviceBusyErrMsg = "device or resource busy"

type Geneve struct {
	ENI
	DestinationIPAddress net.IP
	DestinationPort      uint16
	VNI                  uint32
	Primary              bool
}

// NewGeneve creates a new Geneve object.
func NewGeneve(
	linkName string,
	destinationIP net.IP,
	destinationPort uint16,
	vni string,
	primary bool) (*Geneve, error) {
	if linkName == "" {
		return nil, fmt.Errorf("Link name cannot be empty")
	}
	if vni == "" {
		return nil, fmt.Errorf("VNI cannot be empty")
	}
	if destinationIP == nil {
		return nil, fmt.Errorf("tunnel interface IP cannot be empty")
	}
	if destinationPort == 0 {
		return nil, fmt.Errorf("destination port number cannot be empty")
	}

	vniID, err := strconv.ParseInt(vni, 16, 32)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse VNI")
	}

	geneve := &Geneve{
		ENI: ENI{
			linkName: linkName,
		},
		DestinationIPAddress: destinationIP,
		DestinationPort:      destinationPort,
		VNI:                  uint32(vniID),
		Primary:              primary,
	}

	return geneve, nil
}

// AttachToLink attaches the Geneve object to an interface.
func (geneve *Geneve) AttachToLink() error {
	la := netlink.NewLinkAttrs()
	la.Name = geneve.linkName
	la.MTU = vpc.JumboFrameMTU

	geneveLink := &netlink.Geneve{
		LinkAttrs: la,
		Remote:    geneve.DestinationIPAddress,
		Dport:     geneve.DestinationPort,
		ID:        geneve.VNI,
	}

	log.Infof("Creating Geneve interface %s: %+v", geneve.linkName, geneveLink)
	err := netlink.LinkAdd(geneveLink)
	if err != nil {
		// Depending on which namespace the existing GENEVE interface is in currently,
		// we will either get a "file exists" (default namespace) or "device or resource busy"
		// (custom namespace) error.
		if os.IsExist(err) || err.Error() == DeviceBusyErrMsg {
			log.Infof("Found existing Geneve interface %s.", geneve.linkName)
		} else {
			log.Errorf("Failed to add Geneve interface %s: %v", geneve.linkName, err)
		}

		return err
	}

	// Attach inner ENI object so that the link index and MAC address values will be stored as well.
	// This is done because we do not specify MAC address while creating the GENEVE interface and
	// we need to know the OS assigned MAC address so that it can be included in the plugin
	// execution results.
	if err = geneve.ENI.AttachToLink(); err != nil {
		log.Errorf("Failed to attach geneve object to interface %s: %v", geneve.linkName, err)
		return err
	}

	return nil
}

// DetachFromLink detaches the GENEVE object from a link.
func (geneve *Geneve) DetachFromLink() error {
	// Delete the GENEVE link.
	la := netlink.NewLinkAttrs()
	la.Name = geneve.linkName
	geneveLink := &netlink.Geneve{LinkAttrs: la}

	log.Infof("Deleting geneve link for branch %s: %+v", geneve.linkName, geneveLink)
	err := netlink.LinkDel(geneveLink)
	if err != nil {
		log.Errorf("Failed to delete geneve link %s: %v", geneve.linkName, err)
		return err
	}

	geneve.linkIndex = 0
	return nil
}
