package core

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

type WireGuardPeer struct {
	Name       string
	PublicKey  string
	Endpoint   string
	AllowedIPs []string
}

type WireGuardNode struct {
	Name       string
	PrivateKey string
	ListenPort int
	Address    string
	Peers      []WireGuardPeer
}

func (n WireGuardNode) Validate() error {
	if n.Name == "" {
		return fmt.Errorf("wireguard node name is required")
	}
	if n.PrivateKey == "" {
		return fmt.Errorf("wireguard private key is required")
	}
	if n.ListenPort <= 0 || n.ListenPort > 65535 {
		return fmt.Errorf("wireguard listen port must be between 1 and 65535")
	}
	if _, _, err := net.ParseCIDR(n.Address); err != nil {
		return fmt.Errorf("invalid wireguard address: %w", err)
	}
	for _, peer := range n.Peers {
		if err := peer.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (p WireGuardPeer) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("wireguard peer name is required")
	}
	if p.PublicKey == "" {
		return fmt.Errorf("wireguard peer %q public key is required", p.Name)
	}
	for _, allowed := range p.AllowedIPs {
		if _, _, err := net.ParseCIDR(allowed); err != nil {
			return fmt.Errorf("wireguard peer %q invalid allowed ip %q: %w", p.Name, allowed, err)
		}
	}
	return nil
}

func (n WireGuardNode) RenderConfig() (string, error) {
	if err := n.Validate(); err != nil {
		return "", err
	}

	peers := append([]WireGuardPeer(nil), n.Peers...)
	sort.Slice(peers, func(i, j int) bool { return peers[i].Name < peers[j].Name })

	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\n", n.Address)
	fmt.Fprintf(&b, "ListenPort = %d\n", n.ListenPort)
	fmt.Fprintf(&b, "PrivateKey = %s\n", n.PrivateKey)
	for _, peer := range peers {
		allowed := append([]string(nil), peer.AllowedIPs...)
		sort.Strings(allowed)
		fmt.Fprintf(&b, "\n# %s\n", peer.Name)
		fmt.Fprintf(&b, "[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", peer.PublicKey)
		if peer.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", peer.Endpoint)
		}
		fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
	}
	return b.String(), nil
}
