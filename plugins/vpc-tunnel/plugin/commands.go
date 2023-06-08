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

package plugin

import (
	"fmt"
	"net"
	"os"

	"github.com/aws/amazon-vpc-cni-plugins/network/eni"
	"github.com/aws/amazon-vpc-cni-plugins/network/netns"
	"github.com/aws/amazon-vpc-cni-plugins/network/vpc"
	"github.com/aws/amazon-vpc-cni-plugins/plugins/vpc-tunnel/config"

	log "github.com/cihub/seelog"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesCurrent "github.com/containernetworking/cni/pkg/types/100"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	// Name templates used for objects created by this plugin.
	GeneveLinkNameFormat = "gnv%s%d"
	bridgeNameFormat     = "gnvbr%s%d"

	// The default MAC address for the geneve interface can be any valid MAC address
	// since there isn't an actual device as the gateway. The gateway IP address is
	// just another IP from the same subnet as the primary IP address of the geneve interface.
	defaultGatewayMacAddr = "00:aa:bb:cc:dd:ee"
)

// Add is the internal implementation of CNI ADD command.
func (plugin *Plugin) Add(args *cniSkel.CmdArgs) error {
	// Parse network configuration.
	netConfig, err := config.New(args)
	if err != nil {
		log.Errorf("Failed to parse netconfig from args: %v.", err)
		return err
	}

	log.Infof("Executing ADD with netconfig: %+v.", netConfig)

	// Find the network namespace.
	log.Infof("Searching for netns %s.", args.Netns)
	ns, err := netns.GetNetNS(args.Netns)
	if err != nil {
		log.Errorf("Failed to find netns %s: %v.", args.Netns, err)
		return err
	}

	// Create the Geneve object.
	geneveName := fmt.Sprintf(GeneveLinkNameFormat, netConfig.VNI, netConfig.DestinationPort)
	geneve, err := eni.NewGeneve(
		geneveName,
		netConfig.DestinationIPAddress,
		netConfig.DestinationPort,
		netConfig.VNI,
		netConfig.Primary)
	if err != nil {
		log.Errorf("Failed to create geneve object %s: %v.", geneveName, err)
		return err
	}

	// Create an interface for the geneve object.
	log.Infof("Creating geneve link %s.", geneveName)
	err = plugin.createGeneveLink(geneve, netConfig, ns)
	if err != nil {
		return err
	}

	// Complete the remaining setup in target network namespace.
	err = ns.Run(func() error {
		var err error

		// Create the container-facing link based on the requested interface type.
		switch netConfig.InterfaceType {
		case config.IfTypeGeneve:
			// Container is running in a network namespace on this host.
			err = plugin.configureGeneveLink(geneve, netConfig.IPAddresses, netConfig.GatewayIPAddress)
		case config.IfTypeTAP:
			// Container is running in a VM.
			// Connect the geneve interface to a TAP link in the target network namespace.
			bridgeName := fmt.Sprintf(bridgeNameFormat, netConfig.VNI, netConfig.DestinationPort)
			err = plugin.createTapLink(geneve, bridgeName, args.IfName, netConfig.Tap)
		}

		return err
	})

	if err != nil {
		log.Errorf("Failed to setup the link: %v.", err)
		return err
	}

	// Generate CNI result.
	// IP addresses, routes and DNS are configured by VPC DHCP servers.
	result := &cniTypesCurrent.Result{
		Interfaces: []*cniTypesCurrent.Interface{
			{
				Name:    args.IfName,
				Sandbox: args.Netns,
				Mac:     geneve.GetMACAddress().String(),
			},
		},
	}

	log.Infof("Writing CNI result to stdout: %+v", result)

	return cniTypes.PrintResult(result, netConfig.CNIVersion)
}

// Del is the internal implementation of CNI DEL command.
// CNI DEL command can be called by the orchestrator agent multiple times for the same interface,
// and thus must be best-effort and idempotent.
func (plugin *Plugin) Del(args *cniSkel.CmdArgs) error {
	// Parse network configuration.
	netConfig, err := config.New(args)
	if err != nil {
		log.Errorf("Failed to parse netconfig from args: %v.", err)
		return err
	}

	log.Infof("Executing DEL with netconfig: %+v.", netConfig)

	// Derive names from CNI network config.
	geneveName := fmt.Sprintf(GeneveLinkNameFormat, netConfig.VNI, netConfig.DestinationPort)
	tapBridgeName := fmt.Sprintf(bridgeNameFormat, netConfig.VNI, netConfig.DestinationPort)
	tapLinkName := args.IfName

	geneve, err := eni.NewGeneve(
		geneveName,
		netConfig.DestinationIPAddress,
		netConfig.DestinationPort,
		netConfig.VNI,
		netConfig.Primary)
	if err != nil {
		log.Errorf("Failed to create geneve object %s: %v.", geneveName, err)
		return err
	}

	// Search for the target network namespace.
	netns, err := netns.GetNetNS(args.Netns)
	if err == nil {
		// In target network namespace...
		err = netns.Run(func() error {
			var err error
			if netConfig.InterfaceType == config.IfTypeTAP {
				// Delete the tap link.
				la := netlink.NewLinkAttrs()
				la.Name = tapLinkName
				tapLink := &netlink.Tuntap{LinkAttrs: la}
				log.Infof("Deleting tap link: %v.", tapLinkName)
				err = netlink.LinkDel(tapLink)
				if err != nil {
					// We are not returning the error here because it is important to attempt
					// deleting the remaining resources as well.
					log.Errorf("Failed to delete tap link: %v.", err)
				}
			}

			// Delete the geneve link.
			log.Infof("Deleting geneve link: %v.", geneveName)
			err = geneve.DetachFromLink()
			if err != nil {
				// We are not returning the error here because it is important to attempt
				// deleting the remaining resources as well.
				log.Errorf("Failed to delete geneve link: %v.", err)
			}

			if netConfig.InterfaceType == config.IfTypeTAP {
				// Delete the tap bridge.
				la := netlink.NewLinkAttrs()
				la.Name = tapBridgeName
				tapBridge := &netlink.Bridge{LinkAttrs: la}
				log.Infof("Deleting tap bridge: %v.", tapBridgeName)
				err = netlink.LinkDel(tapBridge)
				if err != nil {
					log.Errorf("Failed to delete tap bridge: %v.", err)
				}
			}

			return nil
		})
		if err != nil {
			log.Errorf("Failed to set netns %s, ignoring: %v.", args.Netns, err)
		}
	} else {
		// Log and ignore the failure. DEL can be called multiple times and thus must be idempotent.
		log.Errorf("Failed to find netns %s, ignoring: %v.", args.Netns, err)
	}

	return nil
}

// createGeneveLink creates the GENEVE interface and moves it to desired netns.
// If it already exists and is the primary interface, it is reset.
func (plugin *Plugin) createGeneveLink(
	geneve *eni.Geneve,
	netConfig *config.NetConfig,
	ns netns.NetNS) error {

	err := geneve.AttachToLink()
	if err != nil {
		// Depending on which namespace the existing GENEVE interface is in currently,
		// we will either get a "file exists" (default namespace) or "device or resource busy"
		// (custom namespace) error.
		if os.IsExist(err) || err.Error() == eni.DeviceBusyErrMsg {
			// If the geneve link already exists, it may have been created in a previous invocation
			// of this plugin. Look for it in the target network namespace and reset it.
			err = ns.Run(func() error {
				err := geneve.ENI.AttachToLink()
				if err != nil {
					return err
				}

				// IP address and routing rules are only put in place for the interface
				// only if it was the primary interface. So for non primary interface,
				// we do not have to delete the same while reseting.
				if geneve.Primary {
					if err = plugin.resetGeneveLink(geneve, netConfig); err != nil {
						log.Errorf("Failed to reset geneve link: %v.", err)
						return err
					}
				}
				return nil
			})
		}
		if err != nil {
			log.Errorf("Failed to attach geneve interface %s: %v.", geneve.ENI.GetLinkName(), err)
			return err
		}
	} else {
		// Move GENEVE link to the network namespace.
		log.Infof("Moving geneve link %s to netns %s.", geneve, ns.GetPath())
		err = geneve.SetNetNS(ns)
		if err != nil {
			log.Errorf("Failed to move geneve link: %v.", err)
			return err
		}
	}

	return err
}

// resetGeneveLink deletes all IP addresses, routes and ARP table entries related to the GENEVE
// interface thus resetting it.
func (plugin *Plugin) resetGeneveLink(geneve *eni.Geneve, netConfig *config.NetConfig) error {
	hwAddr, err := net.ParseMAC(defaultGatewayMacAddr)
	if err != nil {
		return err
	}

	neigh := &netlink.Neigh{
		IP:           netConfig.GatewayIPAddress,
		HardwareAddr: hwAddr,
		LinkIndex:    geneve.GetLinkIndex(),
	}
	log.Infof("Deleting neighbour %+v.", neigh)
	if err = netlink.NeighDel(neigh); err != nil {
		return err
	}

	route := &netlink.Route{
		Gw:        netConfig.GatewayIPAddress,
		LinkIndex: geneve.GetLinkIndex(),
	}
	log.Infof("Deleting default IP route %+v.", route)
	err = netlink.RouteDel(route)
	if err != nil {
		// Trying to delete a route which does not exist will yield a 'no such process error'.
		if err.Error() != "no such process" {
			return err
		}
	}

	for _, ipAddr := range netConfig.IPAddresses {
		err = geneve.DeleteIPAddress(&ipAddr)
		if !os.IsNotExist(err) {
			return err
		}
	}

	return nil
}

// configureGeneveLink creates a VLAN link in the target network namespace.
func (plugin *Plugin) configureGeneveLink(
	geneve *eni.Geneve,
	ipAddresses []net.IPNet,
	gatewayIPAddress net.IP) error {

	// Set GENEVE link operational state up.
	err := geneve.SetOpState(true)
	if err != nil {
		log.Errorf("Failed to set geneve link %v state: %v.", geneve, err)
		return err
	}

	// IP addresses and route rules have to be configured only if the interface is
	// a primary interface.
	if !geneve.Primary {
		return nil
	}

	// Set GENEVE IP addresses if specified.
	for _, ipAddress := range ipAddresses {
		// Assign the IP address.
		log.Infof("Assigning IP address %v to geneve link.", ipAddress)
		err = geneve.AddIPAddress(&ipAddress)
		if err != nil {
			log.Errorf("Failed to assign IP address to geneve link %v: %v.", geneve, err)
			return err
		}
	}

	// Set default gateway interface specified. In this case, there is no actual gateway device that
	// assumes this IP address. The gateway IP address is just another IP from the same subnet as
	// the primary IP address of the geneve interface to ensure all traffic flows through the interface.
	route := &netlink.Route{
		Gw:        gatewayIPAddress,
		LinkIndex: geneve.GetLinkIndex(),
	}
	log.Infof("Adding default IP route %+v.", route)
	err = netlink.RouteAdd(route)
	if err != nil {
		log.Errorf("Failed to add IP route %+v via geneve %v: %v.", route, geneve, err)
		return err
	}

	// Associate a MAC address with the gateway IP address.
	hwAddr, err := net.ParseMAC(defaultGatewayMacAddr)
	if err != nil {
		log.Errorf("Failed to parse hardware address %s for adding neighbour: %v.", defaultGatewayMacAddr, err)
		return err
	}
	neigh := &netlink.Neigh{
		IP:           gatewayIPAddress,
		HardwareAddr: hwAddr,
		LinkIndex:    geneve.GetLinkIndex(),
		Type:         unix.ARPHRD_ETHER,
		State:        netlink.NUD_PERMANENT,
	}
	log.Infof("Adding neighbour %+v.", neigh)
	if err = netlink.NeighAdd(neigh); err != nil {
		log.Errorf("Failed to add neighbour %+v via geneve %v: %v.", neigh, geneve, err)
		return err
	}

	return nil
}

// createTapLink creates a TAP link and a bridge in the target network namespace.
// It also sets the bridge as the master of the TAP link and the ENI link that is
// passed to it so that traffic may flow from the ENI to the TAP link.
func (plugin *Plugin) createTapLink(
	geneve *eni.Geneve,
	bridgeName string,
	tapLinkName string,
	tapCfg *config.TAPConfig) error {

	// Create the bridge link.
	la := netlink.NewLinkAttrs()
	la.Name = bridgeName
	la.MTU = vpc.JumboFrameMTU
	bridge := &netlink.Bridge{LinkAttrs: la}
	log.Infof("Creating bridge geneve %+v.", bridge)
	err := netlink.LinkAdd(bridge)
	if err != nil {
		log.Errorf("Failed to create bridge geneve: %v", err)
		return err
	}

	// Set bridge link MTU.
	err = netlink.LinkSetMTU(bridge, vpc.JumboFrameMTU)
	if err != nil {
		log.Errorf("Failed to set bridge geneve MTU: %v", err)
		return err
	}

	// In TAP mode, the geneve ENI's MAC address is used exclusively by the consumer of the TAP
	// interface (e.g. a VM), so it shouldn't be assigned to the geneve itself. However, this
	// can happen if the geneve is being reused between successive invocations of the plugin.
	// Overriding the geneve's MAC address with that of the bridge prevents that.
	bridgeLink, err := netlink.LinkByIndex(bridge.Index)
	if err != nil {
		log.Errorf("Failed to find bridge geneve: %v", err)
		return err
	}

	err = geneve.SetMACAddress(bridgeLink.Attrs().HardwareAddr)
	if err != nil {
		log.Errorf("Failed to set interface MAC address: %v.", err)
		return err
	}
	log.Infof("Interface mac address set %v", bridgeLink.Attrs().HardwareAddr)

	// Set bridge operational state up.
	err = netlink.LinkSetUp(bridge)
	if err != nil {
		log.Errorf("Failed to set bridge geneve state: %v", err)
		return err
	}

	// Connect geneve link to the bridge.
	la = netlink.NewLinkAttrs()
	la.Name = geneve.GetLinkName()
	geneveLink := &netlink.Dummy{LinkAttrs: la}
	err = netlink.LinkSetMaster(geneveLink, bridge)
	if err != nil {
		log.Errorf("Failed to set geneve master: %v", err)
		return err
	}

	// Create the TAP geneve.
	// Parse headers added by virtio_net implementation.
	la = netlink.NewLinkAttrs()
	la.Name = tapLinkName
	la.MasterIndex = bridge.Index
	la.MTU = vpc.JumboFrameMTU
	tapLink := &netlink.Tuntap{
		LinkAttrs: la,
		Mode:      netlink.TUNTAP_MODE_TAP,
		Flags:     netlink.TUNTAP_VNET_HDR,
		Queues:    tapCfg.Queues,
	}

	if tapCfg.Queues == 1 {
		tapLink.Flags |= netlink.TUNTAP_ONE_QUEUE
	}

	log.Infof("Creating TAP geneve %+v.", tapLink)
	err = netlink.LinkAdd(tapLink)
	if err != nil {
		log.Errorf("Failed to add TAP geneve: %v", err)
		return err
	}

	// Set TAP link MTU.
	err = netlink.LinkSetMTU(tapLink, vpc.JumboFrameMTU)
	if err != nil {
		log.Errorf("Failed to set TAP geneve MTU: %v", err)
		return err
	}

	// Set TAP link ownership.
	log.Infof("Setting TAP geneve owner to UID %d and GID %d.", tapCfg.Uid, tapCfg.Gid)
	for _, tapFd := range tapLink.Fds {
		fd := int(tapFd.Fd())

		err = unix.IoctlSetInt(fd, unix.TUNSETOWNER, tapCfg.Uid)
		if err != nil {
			log.Errorf("Failed to set TAP geneve UID: %v", err)
			return err
		}
		err = unix.IoctlSetInt(fd, unix.TUNSETGROUP, tapCfg.Gid)
		if err != nil {
			log.Errorf("Failed to set TAP geneve GID: %v", err)
			return err
		}

		tapFd.Close()
	}

	// Set TAP link operational state up.
	err = netlink.LinkSetUp(tapLink)
	if err != nil {
		log.Errorf("Failed to set TAP geneve state: %v", err)
		return err
	}

	return nil
}
