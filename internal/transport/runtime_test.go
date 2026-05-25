package transport

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSwitchRuntimeAppliesAndReportsSelection(t *testing.T) {
	reporter := &recordingSwitchReporter{}
	runtime, err := NewSwitchRuntime(ProtocolHysteria2, time.Minute, reporter)
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)

	report, err := runtime.Evaluate(context.Background(), now, Signals{LinkClass: LinkDedicated, UDPAvailable: true}, func(ctx context.Context, protocol Protocol) error {
		if protocol != ProtocolWireGuard {
			t.Fatalf("expected apply %s, got %s", ProtocolWireGuard, protocol)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if runtime.Active() != ProtocolWireGuard || !report.Applied {
		t.Fatalf("expected applied wireguard, active=%s report=%+v", runtime.Active(), report)
	}
	if len(reporter.reports) != 1 || reporter.reports[0].Selected != ProtocolWireGuard {
		t.Fatalf("expected switch report, got %+v", reporter.reports)
	}
}

func TestSwitchRuntimeSuppressesCooldown(t *testing.T) {
	runtime, err := NewSwitchRuntime(ProtocolHysteria2, time.Minute, nil)
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	_, err = runtime.Evaluate(context.Background(), now, Signals{LinkClass: LinkDedicated, UDPAvailable: true}, func(ctx context.Context, protocol Protocol) error {
		return nil
	})
	if err != nil {
		t.Fatalf("first evaluate: %v", err)
	}

	report, err := runtime.Evaluate(context.Background(), now.Add(10*time.Second), Signals{
		LinkClass:    LinkPublic,
		UDPAvailable: true,
		QoSRisk:      true,
	}, func(ctx context.Context, protocol Protocol) error {
		t.Fatalf("apply should not be called during cooldown")
		return nil
	})
	if err != nil {
		t.Fatalf("cooldown evaluate: %v", err)
	}
	if !report.Suppressed || runtime.Active() != ProtocolWireGuard {
		t.Fatalf("expected suppressed switch with active wireguard, active=%s report=%+v", runtime.Active(), report)
	}
}

func TestSwitchRuntimeRollsBackOnApplyFailure(t *testing.T) {
	runtime, err := NewSwitchRuntime(ProtocolHysteria2, 0, nil)
	if err != nil {
		t.Fatalf("new runtime: %v", err)
	}
	applyErr := errors.New("spawn hysteria2 failed")

	report, err := runtime.Evaluate(context.Background(), time.Now(), Signals{LinkClass: LinkDedicated, UDPAvailable: true}, func(ctx context.Context, protocol Protocol) error {
		return applyErr
	})
	if err != nil {
		t.Fatalf("evaluate should report rollback without returning apply error: %v", err)
	}
	if !report.RolledBack || report.Error != applyErr.Error() || runtime.Active() != ProtocolHysteria2 {
		t.Fatalf("expected rollback to hysteria2, active=%s report=%+v", runtime.Active(), report)
	}
}

type recordingSwitchReporter struct {
	reports []SwitchReport
}

func (r *recordingSwitchReporter) ReportTransportSwitch(ctx context.Context, report SwitchReport) error {
	r.reports = append(r.reports, report)
	return nil
}
