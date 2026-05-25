package transport

import "fmt"

const MinHandshakeSuccessRate = 0.5

type Selection struct {
	Protocol  Protocol   `json:"protocol"`
	Reason    string     `json:"reason"`
	Fallbacks []Protocol `json:"fallbacks"`
}

type Selector struct{}

func NewSelector() Selector {
	return Selector{}
}

func (Selector) Select(signals Signals) Selection {
	if err := signals.Validate(); err != nil {
		return selection(ProtocolHysteria2, "invalid link signals; use primary cross-border transport")
	}

	var selected Selection
	if !signals.UDPAvailable {
		selected = selection(ProtocolReality, "udp unavailable; choose tls-shaped fallback")
		return applyHandshakeFallback(selected, signals)
	}
	if signals.DPIRisk || signals.QoSRisk {
		selected = selection(ProtocolReality, "dpi or qos risk detected")
		return applyHandshakeFallback(selected, signals)
	}

	switch signals.LinkClass {
	case LinkDedicated:
		selected = selection(ProtocolWireGuard, "dedicated or trusted link detected")
	case LinkMobile:
		selected = selection(ProtocolHysteria2, "mobile link detected; prefer quic transport")
	case LinkPublic, LinkUnknown:
		selected = selection(ProtocolHysteria2, "public link detected; prefer primary cross-border transport")
	default:
		selected = selection(ProtocolHysteria2, "unclassified link; use primary cross-border transport")
	}
	return applyHandshakeFallback(selected, signals)
}

func selection(protocol Protocol, reason string) Selection {
	return Selection{
		Protocol:  protocol,
		Reason:    reason,
		Fallbacks: fallbacks(protocol),
	}
}

func applyHandshakeFallback(selected Selection, signals Signals) Selection {
	rate, ok := signals.HandshakeSuccess[selected.Protocol]
	if !ok || rate >= MinHandshakeSuccessRate {
		return selected
	}
	for _, fallback := range selected.Fallbacks {
		fallbackRate, ok := signals.HandshakeSuccess[fallback]
		if ok && fallbackRate >= MinHandshakeSuccessRate {
			reason := fmt.Sprintf("%s; %s handshake success %.0f%% below threshold, fallback to %s", selected.Reason, selected.Protocol, rate*100, fallback)
			return selection(fallback, reason)
		}
	}
	return selected
}

func fallbacks(protocol Protocol) []Protocol {
	switch protocol {
	case ProtocolWireGuard:
		return []Protocol{ProtocolHysteria2, ProtocolReality, ProtocolTUIC}
	case ProtocolHysteria2:
		return []Protocol{ProtocolReality, ProtocolTUIC, ProtocolWireGuard}
	case ProtocolReality:
		return []Protocol{ProtocolHysteria2, ProtocolTUIC, ProtocolWireGuard}
	case ProtocolTUIC:
		return []Protocol{ProtocolHysteria2, ProtocolReality, ProtocolWireGuard}
	default:
		return []Protocol{ProtocolHysteria2, ProtocolReality, ProtocolTUIC, ProtocolWireGuard}
	}
}
