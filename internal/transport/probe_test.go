package transport

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNetworkProberChecksTCPRoundTrip(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		skipSocketRestricted(t, err)
		t.Fatalf("listen tcp: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	result := NetworkProber{}.Probe(context.Background(), ProbeTarget{
		Network: "tcp",
		Address: listener.Addr().String(),
		Timeout: time.Second,
	}, time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC))
	if !result.Success || result.Error != "" {
		t.Fatalf("expected tcp probe success, got %+v", result)
	}
}

func TestNetworkProberChecksUDPRoundTrip(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		skipSocketRestricted(t, err)
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()
	go func() {
		buf := make([]byte, 64)
		n, addr, err := conn.ReadFrom(buf)
		if err == nil {
			_, _ = conn.WriteTo(buf[:n], addr)
		}
	}()

	result := NetworkProber{}.Probe(context.Background(), ProbeTarget{
		Network: "udp",
		Address: conn.LocalAddr().String(),
		Timeout: time.Second,
	}, time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC))
	if !result.Success || result.Error != "" {
		t.Fatalf("expected udp probe success, got %+v", result)
	}
}

func TestSignalsFromProbeResultsAggregatesAvailabilityAndRisk(t *testing.T) {
	signals := SignalsFromProbeResults(LinkPublic, []ProbeResult{
		{Network: "udp", Success: true, RTTMillis: 20},
		{Network: "tcp", Success: false},
		{Network: "tcp", Success: true, RTTMillis: 40},
	})

	if !signals.UDPAvailable {
		t.Fatal("expected UDP to be available")
	}
	if signals.PacketLossPermil != 333 {
		t.Fatalf("expected packet loss 333 permil, got %d", signals.PacketLossPermil)
	}
	if !signals.QoSRisk {
		t.Fatal("expected qos risk from packet loss")
	}
}

func TestRunProbeLoopAggregatesAndStopsOnContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var got []Signals
	prober := fakeProber{result: ProbeResult{Network: "udp", Success: true, RTTMillis: 15}}

	err := RunProbeLoop(ctx, prober, []ProbeTarget{{Network: "udp", Address: "127.0.0.1:1"}}, LinkMobile, time.Millisecond, func(signals Signals) {
		got = append(got, signals)
		cancel()
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one signal callback, got %d", len(got))
	}
	if got[0].LinkClass != LinkMobile || !got[0].UDPAvailable {
		t.Fatalf("unexpected signals: %+v", got[0])
	}
}

type fakeProber struct {
	result ProbeResult
}

func (f fakeProber) Probe(ctx context.Context, target ProbeTarget, now time.Time) ProbeResult {
	result := f.result
	result.Network = target.Network
	result.Address = target.Address
	result.CheckedAt = now
	return result
}

func skipSocketRestricted(t *testing.T, err error) {
	t.Helper()
	if strings.Contains(err.Error(), "operation not permitted") {
		t.Skipf("local sockets are restricted in this environment: %v", err)
	}
}
