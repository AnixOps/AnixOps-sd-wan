package transport

import "fmt"

type Protocol string

const (
	ProtocolWireGuard Protocol = "native-wireguard"
	ProtocolHysteria2 Protocol = "hysteria2"
	ProtocolReality   Protocol = "reality"
	ProtocolTUIC      Protocol = "tuic"
)

func (p Protocol) String() string {
	return string(p)
}

func KnownProtocol(p Protocol) bool {
	switch p {
	case ProtocolWireGuard, ProtocolHysteria2, ProtocolReality, ProtocolTUIC:
		return true
	default:
		return false
	}
}

type LinkClass string

const (
	LinkUnknown   LinkClass = "unknown"
	LinkDedicated LinkClass = "dedicated"
	LinkPublic    LinkClass = "public"
	LinkMobile    LinkClass = "mobile"
)

type Signals struct {
	LinkClass        LinkClass
	UDPAvailable     bool
	QoSRisk          bool
	DPIRisk          bool
	RTTMillis        int
	PacketLossPermil int
	JitterMillis     int
	HandshakeSuccess map[Protocol]float64
}

func (s Signals) Validate() error {
	if s.LinkClass == "" {
		return fmt.Errorf("link class is required")
	}
	if s.RTTMillis < 0 {
		return fmt.Errorf("rtt must be non-negative")
	}
	if s.PacketLossPermil < 0 {
		return fmt.Errorf("packet loss must be non-negative")
	}
	if s.JitterMillis < 0 {
		return fmt.Errorf("jitter must be non-negative")
	}
	for protocol, rate := range s.HandshakeSuccess {
		if !KnownProtocol(protocol) {
			return fmt.Errorf("unknown handshake protocol %q", protocol)
		}
		if rate < 0 || rate > 1 {
			return fmt.Errorf("handshake success rate for %s must be between 0 and 1", protocol)
		}
	}
	return nil
}
