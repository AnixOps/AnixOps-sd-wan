package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/transport"
)

func TestServiceStartsWithDefaultSelection(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	snapshot := svc.Snapshot()
	if snapshot.Protocol != transport.ProtocolHysteria2 {
		t.Fatalf("expected default protocol %s, got %s", transport.ProtocolHysteria2, snapshot.Protocol)
	}
	if snapshot.DeviceID == "" || snapshot.TenantID == "" {
		t.Fatalf("expected agent identity in snapshot: %+v", snapshot)
	}
	if snapshot.LinkClass != transport.LinkUnknown || !snapshot.UDPAvailable {
		t.Fatalf("expected default link metrics in snapshot: %+v", snapshot)
	}
}

func TestServiceEvaluatesDedicatedLinks(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	snapshot := svc.Evaluate(transport.Signals{LinkClass: transport.LinkDedicated, UDPAvailable: true})
	if snapshot.Protocol != transport.ProtocolWireGuard {
		t.Fatalf("expected %s, got %s", transport.ProtocolWireGuard, snapshot.Protocol)
	}
	if snapshot.LinkClass != transport.LinkDedicated || !snapshot.UDPAvailable {
		t.Fatalf("expected dedicated metrics in snapshot: %+v", snapshot)
	}
}

func TestServiceRequiresTransportRuntimeAndApplyTogether(t *testing.T) {
	runtime, err := transport.NewSwitchRuntime(transport.ProtocolHysteria2, 0, nil)
	if err != nil {
		t.Fatalf("new switch runtime: %v", err)
	}
	if _, err := NewServiceWithTransportRuntime(config.Default(), nil, runtime, nil); err == nil {
		t.Fatal("expected runtime without apply to be rejected")
	}
	if _, err := NewServiceWithTransportRuntime(config.Default(), nil, nil, func(ctx context.Context, protocol transport.Protocol) error {
		return nil
	}); err == nil {
		t.Fatal("expected apply without runtime to be rejected")
	}
}

func TestServiceStartActivatesInitialTransportRuntime(t *testing.T) {
	runtime, err := transport.NewSwitchRuntime(transport.ProtocolHysteria2, 0, nil)
	if err != nil {
		t.Fatalf("new switch runtime: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var activated []transport.Protocol
	svc, err := NewServiceWithTransportRuntime(config.Default(), nil, runtime, func(ctx context.Context, protocol transport.Protocol) error {
		activated = append(activated, protocol)
		cancel()
		return nil
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start service: %v", err)
	}
	if len(activated) != 1 || activated[0] != transport.ProtocolHysteria2 {
		t.Fatalf("expected initial hysteria2 activation, got %+v", activated)
	}
	if svc.Snapshot().Running {
		t.Fatal("expected snapshot to be stopped after context cancellation")
	}
}

func TestServiceStartReportsInitialTransportFailure(t *testing.T) {
	runtime, err := transport.NewSwitchRuntime(transport.ProtocolHysteria2, 0, nil)
	if err != nil {
		t.Fatalf("new switch runtime: %v", err)
	}
	applyErr := errors.New("missing hysteria binary")
	svc, err := NewServiceWithTransportRuntime(config.Default(), nil, runtime, func(ctx context.Context, protocol transport.Protocol) error {
		return applyErr
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	err = svc.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), applyErr.Error()) {
		t.Fatalf("expected initial transport error, got %v", err)
	}
	if svc.Snapshot().Running {
		t.Fatal("expected failed start to mark snapshot stopped")
	}
}

func TestServiceEvaluateAndApplyUsesTransportRuntime(t *testing.T) {
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

	snapshot, report, err := svc.EvaluateAndApply(context.Background(), transport.Signals{
		LinkClass:        transport.LinkDedicated,
		UDPAvailable:     true,
		RTTMillis:        23,
		PacketLossPermil: 75,
		JitterMillis:     7,
	})
	if err != nil {
		t.Fatalf("evaluate and apply: %v", err)
	}
	if !report.Applied || snapshot.Protocol != transport.ProtocolWireGuard {
		t.Fatalf("expected wireguard switch, snapshot=%+v report=%+v", snapshot, report)
	}
	if snapshot.RTTMillis != 23 || snapshot.PacketLossPermil != 75 || snapshot.JitterMillis != 7 {
		t.Fatalf("expected signals to be stored in snapshot, got %+v", snapshot)
	}
	if len(applied) != 1 || applied[0] != transport.ProtocolWireGuard {
		t.Fatalf("expected wireguard apply call, got %+v", applied)
	}
}

func TestServiceEvaluateAndApplyKeepsActiveProtocolOnApplyFailure(t *testing.T) {
	runtime, err := transport.NewSwitchRuntime(transport.ProtocolHysteria2, 0, nil)
	if err != nil {
		t.Fatalf("new switch runtime: %v", err)
	}
	applyErr := errors.New("wg-quick failed")
	svc, err := NewServiceWithTransportRuntime(config.Default(), nil, runtime, func(ctx context.Context, protocol transport.Protocol) error {
		return applyErr
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	snapshot, report, err := svc.EvaluateAndApply(context.Background(), transport.Signals{
		LinkClass:    transport.LinkDedicated,
		UDPAvailable: true,
	})
	if err != nil {
		t.Fatalf("evaluate and apply should report rollback without returning apply error: %v", err)
	}
	if !report.RolledBack || snapshot.Protocol != transport.ProtocolHysteria2 {
		t.Fatalf("expected rollback to hysteria2, snapshot=%+v report=%+v", snapshot, report)
	}
	if !strings.Contains(snapshot.Reason, applyErr.Error()) {
		t.Fatalf("expected rollback reason to include apply error, got %q", snapshot.Reason)
	}
}

func TestServiceAppliesMatchingConfig(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	if err := svc.ApplyConfig(domain.ConfigBundle{
		ID:       "cfg-1",
		TenantID: "default",
		TargetID: "local-dev",
		Version:  "v2",
	}); err != nil {
		t.Fatalf("apply config: %v", err)
	}
	if got := svc.Snapshot().ConfigVersion; got != "v2" {
		t.Fatalf("expected config version v2, got %s", got)
	}
}

func TestServiceEvaluateAndApplyWithoutRuntimeKeepsSelectionOnlyBehavior(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	snapshot, report, err := svc.EvaluateAndApply(context.Background(), transport.Signals{
		LinkClass:    transport.LinkDedicated,
		UDPAvailable: true,
	})
	if err != nil {
		t.Fatalf("evaluate and apply without runtime: %v", err)
	}
	if snapshot.Protocol != transport.ProtocolWireGuard || !report.Applied {
		t.Fatalf("expected selection-only wireguard, snapshot=%+v report=%+v", snapshot, report)
	}
	if time.Since(snapshot.UpdatedAt) > time.Minute {
		t.Fatalf("expected fresh snapshot update, got %s", snapshot.UpdatedAt)
	}
}

func TestServiceRejectsMismatchedConfig(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	if err := svc.ApplyConfig(domain.ConfigBundle{
		ID:       "cfg-1",
		TenantID: "other",
		TargetID: "local-dev",
		Version:  "v2",
	}); err == nil {
		t.Fatal("expected mismatched tenant config to be rejected")
	}
}

func TestServiceBuildsTelemetryReport(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	report := svc.TelemetryReport()
	if report.TenantID != "default" || report.SubjectID != "local-dev" {
		t.Fatalf("unexpected telemetry identity: %+v", report)
	}
	if len(report.Logs) != 1 {
		t.Fatalf("expected one telemetry log, got %+v", report.Logs)
	}
	if got := report.Metrics["rtt_millis"]; got != 0 {
		t.Fatalf("expected zero default rtt metric, got %v", got)
	}
	if report.Logs[0].Fields["link_class"] != string(transport.LinkUnknown) {
		t.Fatalf("expected link class in telemetry fields, got %+v", report.Logs[0].Fields)
	}
}
