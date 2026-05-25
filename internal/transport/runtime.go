package transport

import (
	"context"
	"fmt"
	"time"
)

type SwitchReport struct {
	Previous    Protocol  `json:"previous"`
	Selected    Protocol  `json:"selected"`
	Applied     bool      `json:"applied"`
	Suppressed  bool      `json:"suppressed"`
	RolledBack  bool      `json:"rolled_back"`
	Reason      string    `json:"reason"`
	Error       string    `json:"error,omitempty"`
	Signals     Signals   `json:"signals"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

type SwitchReporter interface {
	ReportTransportSwitch(context.Context, SwitchReport) error
}

type ApplyFunc func(context.Context, Protocol) error

type SwitchRuntime struct {
	selector   Selector
	active     Protocol
	cooldown   time.Duration
	lastSwitch time.Time
	reporter   SwitchReporter
}

func NewSwitchRuntime(active Protocol, cooldown time.Duration, reporter SwitchReporter) (*SwitchRuntime, error) {
	if !KnownProtocol(active) {
		return nil, fmt.Errorf("active protocol %q is unknown", active)
	}
	if cooldown < 0 {
		return nil, fmt.Errorf("switch cooldown must be non-negative")
	}
	return &SwitchRuntime{
		selector: Selector{},
		active:   active,
		cooldown: cooldown,
		reporter: reporter,
	}, nil
}

func (r *SwitchRuntime) Active() Protocol {
	return r.active
}

func (r *SwitchRuntime) Evaluate(ctx context.Context, now time.Time, signals Signals, apply ApplyFunc) (SwitchReport, error) {
	if err := signals.Validate(); err != nil {
		return SwitchReport{}, err
	}
	if apply == nil {
		return SwitchReport{}, fmt.Errorf("transport apply function is required")
	}

	selection := r.selector.Select(signals)
	report := SwitchReport{
		Previous:    r.active,
		Selected:    selection.Protocol,
		Reason:      selection.Reason,
		Signals:     signals,
		EvaluatedAt: now,
	}
	if selection.Protocol == r.active {
		report.Applied = true
		return report, r.report(ctx, report)
	}
	if !r.lastSwitch.IsZero() && r.cooldown > 0 && now.Sub(r.lastSwitch) < r.cooldown {
		report.Selected = r.active
		report.Suppressed = true
		report.Reason = "switch cooldown active"
		return report, r.report(ctx, report)
	}
	if err := apply(ctx, selection.Protocol); err != nil {
		report.Selected = r.active
		report.RolledBack = true
		report.Error = err.Error()
		return report, r.report(ctx, report)
	}

	r.active = selection.Protocol
	r.lastSwitch = now
	report.Applied = true
	return report, r.report(ctx, report)
}

func (r *SwitchRuntime) report(ctx context.Context, report SwitchReport) error {
	if r.reporter == nil {
		return nil
	}
	if err := r.reporter.ReportTransportSwitch(ctx, report); err != nil {
		return fmt.Errorf("report transport switch: %w", err)
	}
	return nil
}
