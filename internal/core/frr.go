package core

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

type BGPNeighbor struct {
	Address  string
	RemoteAS int
	BFD      bool
}

type FRRConfig struct {
	Hostname        string
	RouterID        string
	LocalAS         int
	MaximumPaths    int
	GracefulRestart bool
	Networks        []string
	Neighbors       []BGPNeighbor
}

func (c FRRConfig) Validate() error {
	if c.Hostname == "" {
		return fmt.Errorf("frr hostname is required")
	}
	if net.ParseIP(c.RouterID) == nil {
		return fmt.Errorf("invalid router id")
	}
	if c.LocalAS <= 0 {
		return fmt.Errorf("local as must be positive")
	}
	if c.MaximumPaths < 0 {
		return fmt.Errorf("maximum paths must be non-negative")
	}
	for _, network := range c.Networks {
		if _, _, err := net.ParseCIDR(network); err != nil {
			return fmt.Errorf("invalid bgp network %q: %w", network, err)
		}
	}
	for _, neighbor := range c.Neighbors {
		if err := neighbor.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (n BGPNeighbor) Validate() error {
	if net.ParseIP(n.Address) == nil {
		return fmt.Errorf("invalid bgp neighbor address")
	}
	if n.RemoteAS <= 0 {
		return fmt.Errorf("remote as must be positive")
	}
	return nil
}

func (c FRRConfig) Render() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}

	networks := append([]string(nil), c.Networks...)
	sort.Strings(networks)
	neighbors := append([]BGPNeighbor(nil), c.Neighbors...)
	sort.Slice(neighbors, func(i, j int) bool { return neighbors[i].Address < neighbors[j].Address })

	var b strings.Builder
	fmt.Fprintf(&b, "hostname %s\n", c.Hostname)
	fmt.Fprintf(&b, "router bgp %d\n", c.LocalAS)
	fmt.Fprintf(&b, " bgp router-id %s\n", c.RouterID)
	if c.GracefulRestart {
		fmt.Fprintf(&b, " bgp graceful-restart\n")
	}
	for _, network := range networks {
		fmt.Fprintf(&b, " network %s\n", network)
	}
	for _, neighbor := range neighbors {
		fmt.Fprintf(&b, " neighbor %s remote-as %d\n", neighbor.Address, neighbor.RemoteAS)
		if neighbor.BFD {
			fmt.Fprintf(&b, " neighbor %s bfd\n", neighbor.Address)
		}
	}
	maximumPaths := c.MaximumPaths
	if maximumPaths == 0 {
		maximumPaths = 8
	}
	fmt.Fprintf(&b, " maximum-paths %d\n", maximumPaths)
	return b.String(), nil
}
