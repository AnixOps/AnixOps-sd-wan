package node

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"anixops-sd-wan/internal/domain"
)

type Snapshot struct {
	TenantID      string          `json:"tenant_id"`
	NodeID        string          `json:"node_id"`
	Role          domain.NodeRole `json:"role"`
	Region        string          `json:"region"`
	Endpoint      string          `json:"endpoint,omitempty"`
	Healthy       bool            `json:"healthy"`
	ConfigVersion string          `json:"config_version"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

type SyncClient interface {
	Configs(ctx context.Context, tenantID string) ([]domain.ConfigBundle, error)
	PushNodeHeartbeat(ctx context.Context, tenantID string, heartbeat domain.NodeHeartbeat) (domain.Node, error)
}

type WatchClient interface {
	WatchConfig(ctx context.Context, tenantID, targetID, sinceVersion string, timeout time.Duration) (domain.ConfigBundle, bool, error)
	PushNodeHeartbeat(ctx context.Context, tenantID string, heartbeat domain.NodeHeartbeat) (domain.Node, error)
}

type Service struct {
	mu       sync.RWMutex
	snapshot Snapshot
}

func NewService(snapshot Snapshot) (*Service, error) {
	if err := snapshot.Validate(); err != nil {
		return nil, err
	}
	if snapshot.UpdatedAt.IsZero() {
		snapshot.UpdatedAt = time.Now().UTC()
	}
	return &Service{snapshot: snapshot}, nil
}

func (s Snapshot) Validate() error {
	if strings.TrimSpace(s.TenantID) == "" {
		return fmt.Errorf("node tenant id is required")
	}
	if strings.TrimSpace(s.NodeID) == "" {
		return fmt.Errorf("node id is required")
	}
	if s.Role == "" {
		return fmt.Errorf("node role is required")
	}
	if !validNodeRole(s.Role) {
		return fmt.Errorf("node role %q is unsupported", s.Role)
	}
	if strings.TrimSpace(s.Region) == "" {
		return fmt.Errorf("node region is required")
	}
	return nil
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

	if bundle.TenantID != s.snapshot.TenantID {
		return fmt.Errorf("config tenant %q does not match node tenant %q", bundle.TenantID, s.snapshot.TenantID)
	}
	if bundle.TargetID != s.snapshot.NodeID {
		return fmt.Errorf("config target %q does not match node %q", bundle.TargetID, s.snapshot.NodeID)
	}
	if endpoint := strings.TrimSpace(bundle.Values["endpoint"]); endpoint != "" {
		s.snapshot.Endpoint = endpoint
	}
	if region := strings.TrimSpace(bundle.Values["region"]); region != "" {
		s.snapshot.Region = region
	}
	if rawHealthy := strings.TrimSpace(bundle.Values["healthy"]); rawHealthy != "" {
		healthy, err := strconv.ParseBool(rawHealthy)
		if err != nil {
			return fmt.Errorf("parse node healthy config: %w", err)
		}
		s.snapshot.Healthy = healthy
	}
	s.snapshot.ConfigVersion = bundle.Version
	s.snapshot.UpdatedAt = time.Now().UTC()
	return nil
}

func (s *Service) SyncOnce(ctx context.Context, client SyncClient) error {
	if client == nil {
		return fmt.Errorf("node sync client is required")
	}
	snapshot := s.Snapshot()
	configs, err := client.Configs(ctx, snapshot.TenantID)
	if err != nil {
		return fmt.Errorf("fetch node configs: %w", err)
	}
	if selected, ok := selectConfig(configs, snapshot.NodeID); ok {
		if err := s.ApplyConfig(selected); err != nil {
			return err
		}
		snapshot = s.Snapshot()
	}
	updated, err := client.PushNodeHeartbeat(ctx, snapshot.TenantID, domain.NodeHeartbeat{
		TenantID: snapshot.TenantID,
		NodeID:   snapshot.NodeID,
		Healthy:  snapshot.Healthy,
		Endpoint: snapshot.Endpoint,
	})
	if err != nil {
		return fmt.Errorf("push node heartbeat: %w", err)
	}
	s.observeControlNode(updated)
	return nil
}

func (s *Service) WatchConfigOnce(ctx context.Context, client WatchClient, timeout time.Duration) error {
	if client == nil {
		return fmt.Errorf("node config watch client is required")
	}
	snapshot := s.Snapshot()
	bundle, changed, err := client.WatchConfig(ctx, snapshot.TenantID, snapshot.NodeID, snapshot.ConfigVersion, timeout)
	if err != nil {
		return fmt.Errorf("watch node config: %w", err)
	}
	if changed {
		if err := s.ApplyConfig(bundle); err != nil {
			return err
		}
		snapshot = s.Snapshot()
	}
	updated, err := client.PushNodeHeartbeat(ctx, snapshot.TenantID, domain.NodeHeartbeat{
		TenantID: snapshot.TenantID,
		NodeID:   snapshot.NodeID,
		Healthy:  snapshot.Healthy,
		Endpoint: snapshot.Endpoint,
	})
	if err != nil {
		return fmt.Errorf("push node heartbeat: %w", err)
	}
	s.observeControlNode(updated)
	return nil
}

func (s *Service) RunSyncLoop(ctx context.Context, client SyncClient, interval time.Duration) error {
	if client == nil {
		return fmt.Errorf("node sync client is required")
	}
	if interval <= 0 {
		return fmt.Errorf("node sync interval must be positive")
	}
	for {
		if err := s.SyncOnce(ctx, client); err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *Service) observeControlNode(updated domain.Node) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if updated.TenantID != "" && updated.TenantID != s.snapshot.TenantID {
		return
	}
	if updated.ID != "" && updated.ID != s.snapshot.NodeID {
		return
	}
	if updated.Endpoint != "" {
		s.snapshot.Endpoint = updated.Endpoint
	}
	s.snapshot.Healthy = updated.Healthy
	if !updated.UpdatedAt.IsZero() {
		s.snapshot.UpdatedAt = updated.UpdatedAt
		return
	}
	s.snapshot.UpdatedAt = time.Now().UTC()
}

func selectConfig(configs []domain.ConfigBundle, targetID string) (domain.ConfigBundle, bool) {
	var selected domain.ConfigBundle
	found := false
	for _, candidate := range configs {
		if candidate.TargetID != targetID {
			continue
		}
		if !found || candidate.CreatedAt.After(selected.CreatedAt) || candidate.Version > selected.Version {
			selected = candidate
			found = true
		}
	}
	return selected, found
}

func validNodeRole(role domain.NodeRole) bool {
	switch role {
	case domain.NodeChinaEntry, domain.NodeOverseasEdge, domain.NodeCore, domain.NodeEgress:
		return true
	default:
		return false
	}
}
