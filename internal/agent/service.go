package agent

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/telemetry"
	"anixops-sd-wan/internal/transport"
)

type Snapshot struct {
	TenantID         string              `json:"tenant_id"`
	DeviceID         string              `json:"device_id"`
	Platform         string              `json:"platform"`
	ConfigVersion    string              `json:"config_version"`
	Running          bool                `json:"running"`
	Protocol         transport.Protocol  `json:"protocol"`
	LinkClass        transport.LinkClass `json:"link_class"`
	RTTMillis        int                 `json:"rtt_millis"`
	PacketLossPermil int                 `json:"packet_loss_permil"`
	JitterMillis     int                 `json:"jitter_millis"`
	UDPAvailable     bool                `json:"udp_available"`
	Reason           string              `json:"reason"`
	UpdatedAt        time.Time           `json:"updated_at"`
}

type Service struct {
	mu             sync.RWMutex
	cfg            config.Config
	selector       transport.Selector
	switchRuntime  *transport.SwitchRuntime
	transportApply transport.ApplyFunc
	telemetryQueue TelemetryQueue
	snapshot       Snapshot
	cache          ConfigCache
}

func NewService(cfg config.Config) (*Service, error) {
	return NewServiceWithCache(cfg, nil)
}

func NewServiceWithCache(cfg config.Config, cache ConfigCache) (*Service, error) {
	return newServiceWithDependencies(cfg, cache, nil, nil, nil)
}

func NewServiceWithTransportRuntime(cfg config.Config, cache ConfigCache, runtime *transport.SwitchRuntime, apply transport.ApplyFunc) (*Service, error) {
	return newServiceWithDependencies(cfg, cache, runtime, apply, nil)
}

func NewServiceWithTelemetryQueue(cfg config.Config, cache ConfigCache, queue TelemetryQueue) (*Service, error) {
	return newServiceWithDependencies(cfg, cache, nil, nil, queue)
}

func NewServiceWithTransportRuntimeAndTelemetryQueue(cfg config.Config, cache ConfigCache, runtime *transport.SwitchRuntime, apply transport.ApplyFunc, queue TelemetryQueue) (*Service, error) {
	return newServiceWithDependencies(cfg, cache, runtime, apply, queue)
}

func newServiceWithDependencies(cfg config.Config, cache ConfigCache, runtime *transport.SwitchRuntime, apply transport.ApplyFunc, queue TelemetryQueue) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if runtime != nil && apply == nil {
		return nil, fmt.Errorf("transport apply function is required when transport runtime is configured")
	}
	if runtime == nil && apply != nil {
		return nil, fmt.Errorf("transport runtime is required when transport apply function is configured")
	}
	if cache != nil {
		cached, err := cache.Load()
		if err != nil && !errors.Is(err, ErrConfigCacheMiss) {
			return nil, err
		}
		if err == nil {
			if cached.TenantID != cfg.Agent.TenantID {
				return nil, fmt.Errorf("cached config tenant %q does not match agent tenant %q", cached.TenantID, cfg.Agent.TenantID)
			}
			if cached.TargetID != cfg.Agent.DeviceID {
				return nil, fmt.Errorf("cached config target %q does not match agent device %q", cached.TargetID, cfg.Agent.DeviceID)
			}
			cfg.Agent.ConfigVersion = cached.Version
		}
	}

	service := &Service{
		cfg:            cfg,
		selector:       transport.NewSelector(),
		switchRuntime:  runtime,
		transportApply: apply,
		telemetryQueue: queue,
		cache:          cache,
	}
	if runtime != nil {
		service.snapshot = service.snapshotWithSignalsLocked(runtime.Active(), "transport runtime active", time.Now().UTC(), transport.Signals{
			LinkClass:    transport.LinkUnknown,
			UDPAvailable: true,
		})
	} else {
		service.snapshot = service.evaluateLocked(transport.Signals{
			LinkClass:    transport.LinkUnknown,
			UDPAvailable: true,
		})
	}
	return service, nil
}

func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	s.snapshot.Running = true
	s.snapshot.UpdatedAt = time.Now().UTC()
	initialProtocol := transport.Protocol("")
	initialApply := s.transportApply
	if s.switchRuntime != nil {
		initialProtocol = s.switchRuntime.Active()
	}
	s.mu.Unlock()

	if initialApply != nil {
		if err := initialApply(ctx, initialProtocol); err != nil {
			s.mu.Lock()
			s.snapshot.Running = false
			s.snapshot.UpdatedAt = time.Now().UTC()
			s.mu.Unlock()
			return fmt.Errorf("activate initial transport %s: %w", initialProtocol, err)
		}
	}

	<-ctx.Done()

	s.mu.Lock()
	s.snapshot.Running = false
	s.snapshot.UpdatedAt = time.Now().UTC()
	s.mu.Unlock()

	return nil
}

func (s *Service) Evaluate(signals transport.Signals) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.snapshot = s.evaluateLocked(signals)
	return s.snapshot
}

func (s *Service) EvaluateAndApply(ctx context.Context, signals transport.Signals) (Snapshot, transport.SwitchReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.switchRuntime == nil {
		previous := s.snapshot.Protocol
		s.snapshot = s.evaluateLocked(signals)
		return s.snapshot, transport.SwitchReport{
			Previous:    previous,
			Selected:    s.snapshot.Protocol,
			Applied:     true,
			Reason:      s.snapshot.Reason,
			Signals:     signals,
			EvaluatedAt: s.snapshot.UpdatedAt,
		}, nil
	}

	now := time.Now().UTC()
	report, err := s.switchRuntime.Evaluate(ctx, now, signals, s.transportApply)
	if err != nil {
		return s.snapshot, transport.SwitchReport{}, err
	}
	reason := report.Reason
	if report.RolledBack && report.Error != "" {
		reason = fmt.Sprintf("%s: %s", reason, report.Error)
	}
	s.snapshot = s.snapshotWithSignalsLocked(report.Selected, reason, now, signals)
	return s.snapshot, report, nil
}

func (s *Service) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.snapshot
}

func (s *Service) ApplyConfig(bundle domain.ConfigBundle) error {
	if err := bundle.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if bundle.TenantID != s.cfg.Agent.TenantID {
		return fmt.Errorf("config tenant %q does not match agent tenant %q", bundle.TenantID, s.cfg.Agent.TenantID)
	}
	if bundle.TargetID != s.cfg.Agent.DeviceID {
		return fmt.Errorf("config target %q does not match agent device %q", bundle.TargetID, s.cfg.Agent.DeviceID)
	}
	if s.cache != nil {
		if err := s.cache.Save(bundle); err != nil {
			return fmt.Errorf("save config cache: %w", err)
		}
	}
	if protocol, ok := parseTransportProtocol(bundle.Values["transport"]); ok {
		s.snapshot.Protocol = protocol
	}
	s.cfg.Agent.ConfigVersion = bundle.Version
	s.snapshot.ConfigVersion = bundle.Version
	s.snapshot.UpdatedAt = time.Now().UTC()
	return nil
}

func (s *Service) TelemetryReport() telemetry.Report {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return telemetry.Report{
		TenantID:    s.snapshot.TenantID,
		SubjectID:   s.snapshot.DeviceID,
		SubjectKind: telemetry.SubjectAgent,
		Timestamp:   time.Now().UTC(),
		Metrics: map[string]float64{
			"rtt_millis":         float64(s.snapshot.RTTMillis),
			"packet_loss_permil": float64(s.snapshot.PacketLossPermil),
			"jitter_millis":      float64(s.snapshot.JitterMillis),
			"udp_available":      boolMetric(s.snapshot.UDPAvailable),
		},
		Logs: []telemetry.LogRecord{{
			Level:   "info",
			Message: "agent snapshot",
			Fields: map[string]string{
				"platform":       s.snapshot.Platform,
				"protocol":       s.snapshot.Protocol.String(),
				"config_version": s.snapshot.ConfigVersion,
				"link_class":     string(s.snapshot.LinkClass),
			},
		}},
	}
}

func (s *Service) evaluateLocked(signals transport.Signals) Snapshot {
	selected := s.selector.Select(signals)
	return s.snapshotWithSignalsLocked(selected.Protocol, selected.Reason, time.Now().UTC(), signals)
}

func (s *Service) snapshotWithProtocolLocked(protocol transport.Protocol, reason string, now time.Time) Snapshot {
	return Snapshot{
		TenantID:         s.cfg.Agent.TenantID,
		DeviceID:         s.cfg.Agent.DeviceID,
		Platform:         runtime.GOOS + "/" + runtime.GOARCH,
		ConfigVersion:    s.cfg.Agent.ConfigVersion,
		Running:          s.snapshot.Running,
		Protocol:         protocol,
		LinkClass:        s.snapshot.LinkClass,
		RTTMillis:        s.snapshot.RTTMillis,
		PacketLossPermil: s.snapshot.PacketLossPermil,
		JitterMillis:     s.snapshot.JitterMillis,
		UDPAvailable:     s.snapshot.UDPAvailable,
		Reason:           reason,
		UpdatedAt:        now,
	}
}

func (s *Service) snapshotWithSignalsLocked(protocol transport.Protocol, reason string, now time.Time, signals transport.Signals) Snapshot {
	snapshot := s.snapshotWithProtocolLocked(protocol, reason, now)
	snapshot.LinkClass = signals.LinkClass
	if snapshot.LinkClass == "" {
		snapshot.LinkClass = transport.LinkUnknown
	}
	snapshot.RTTMillis = signals.RTTMillis
	snapshot.PacketLossPermil = signals.PacketLossPermil
	snapshot.JitterMillis = signals.JitterMillis
	snapshot.UDPAvailable = signals.UDPAvailable
	return snapshot
}

func parseTransportProtocol(value string) (transport.Protocol, bool) {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case string(transport.ProtocolWireGuard), "wireguard":
		return transport.ProtocolWireGuard, true
	case string(transport.ProtocolHysteria2):
		return transport.ProtocolHysteria2, true
	case string(transport.ProtocolReality):
		return transport.ProtocolReality, true
	case string(transport.ProtocolTUIC):
		return transport.ProtocolTUIC, true
	default:
		return "", false
	}
}

func boolMetric(value bool) float64 {
	if value {
		return 1
	}
	return 0
}
