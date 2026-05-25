package agent

import (
	"context"
	"time"

	"anixops-sd-wan/internal/transport"
)

func (s *Service) RunProbeLoop(ctx context.Context, prober transport.Prober, targets []transport.ProbeTarget, linkClass transport.LinkClass, interval time.Duration) error {
	var switchErr error
	err := transport.RunProbeLoop(ctx, prober, targets, linkClass, interval, func(signals transport.Signals) {
		s.mu.RLock()
		hasRuntime := s.switchRuntime != nil
		s.mu.RUnlock()
		if hasRuntime {
			if _, _, err := s.EvaluateAndApply(ctx, signals); err != nil && switchErr == nil {
				switchErr = err
			}
			return
		}
		s.Evaluate(signals)
	})
	if switchErr != nil {
		return switchErr
	}
	return err
}
