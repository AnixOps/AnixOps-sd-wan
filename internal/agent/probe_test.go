package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/transport"
)

func TestServiceRunProbeLoopUpdatesSnapshotProtocol(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	prober := agentProbe{cancel: cancel}

	err = svc.RunProbeLoop(ctx, prober, []transport.ProbeTarget{{Network: "udp", Address: "probe.local:443"}}, transport.LinkDedicated, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if got := svc.Snapshot().Protocol; got != transport.ProtocolWireGuard {
		t.Fatalf("expected dedicated link to select wireguard, got %s", got)
	}
}

func TestServiceRunProbeLoopAppliesTransportRuntime(t *testing.T) {
	runtime, err := transport.NewSwitchRuntime(transport.ProtocolHysteria2, 0, nil)
	if err != nil {
		t.Fatalf("new switch runtime: %v", err)
	}
	var applied []transport.Protocol
	svc, err := NewServiceWithTransportRuntime(config.Default(), nil, runtime, func(ctx context.Context, protocol transport.Protocol) error {
		applied = append(applied, protocol)
		return nil
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	prober := agentProbe{cancel: cancel}

	err = svc.RunProbeLoop(ctx, prober, []transport.ProbeTarget{{Network: "udp", Address: "probe.local:443"}}, transport.LinkDedicated, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if len(applied) != 1 || applied[0] != transport.ProtocolWireGuard {
		t.Fatalf("expected probe loop to apply wireguard, got %+v", applied)
	}
	if got := svc.Snapshot().Protocol; got != transport.ProtocolWireGuard {
		t.Fatalf("expected dedicated link to apply wireguard, got %s", got)
	}
}

type agentProbe struct {
	cancel context.CancelFunc
}

func (p agentProbe) Probe(ctx context.Context, target transport.ProbeTarget, now time.Time) transport.ProbeResult {
	p.cancel()
	return transport.ProbeResult{
		Network:   target.Network,
		Address:   target.Address,
		Success:   true,
		RTTMillis: 10,
		CheckedAt: now,
	}
}
