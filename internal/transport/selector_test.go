package transport

import "testing"

func TestSelectorPrefersWireGuardForDedicatedUDPLinks(t *testing.T) {
	got := NewSelector().Select(Signals{LinkClass: LinkDedicated, UDPAvailable: true})

	if got.Protocol != ProtocolWireGuard {
		t.Fatalf("expected %s, got %s", ProtocolWireGuard, got.Protocol)
	}
}

func TestSelectorPrefersRealityForRiskyLinks(t *testing.T) {
	got := NewSelector().Select(Signals{LinkClass: LinkPublic, UDPAvailable: true, DPIRisk: true})

	if got.Protocol != ProtocolReality {
		t.Fatalf("expected %s, got %s", ProtocolReality, got.Protocol)
	}
}

func TestSelectorPrefersHysteria2ForMobileLinks(t *testing.T) {
	got := NewSelector().Select(Signals{LinkClass: LinkMobile, UDPAvailable: true})

	if got.Protocol != ProtocolHysteria2 {
		t.Fatalf("expected %s, got %s", ProtocolHysteria2, got.Protocol)
	}
}

func TestSelectorFallsBackToRealityWithoutUDP(t *testing.T) {
	got := NewSelector().Select(Signals{LinkClass: LinkDedicated, UDPAvailable: false})

	if got.Protocol != ProtocolReality {
		t.Fatalf("expected %s, got %s", ProtocolReality, got.Protocol)
	}
}

func TestSelectorUsesHandshakeSuccessRateFallback(t *testing.T) {
	got := NewSelector().Select(Signals{
		LinkClass:    LinkDedicated,
		UDPAvailable: true,
		HandshakeSuccess: map[Protocol]float64{
			ProtocolWireGuard: 0.2,
			ProtocolHysteria2: 0.9,
		},
	})

	if got.Protocol != ProtocolHysteria2 {
		t.Fatalf("expected %s fallback, got %s", ProtocolHysteria2, got.Protocol)
	}
}
