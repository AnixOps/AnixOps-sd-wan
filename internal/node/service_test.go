package node

import (
	"context"
	"errors"
	"testing"
	"time"

	"anixops-sd-wan/internal/domain"
)

func TestSyncOnceAppliesTargetConfigAndPushesHeartbeat(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	svc := newTestService(t)
	client := &fakeSyncClient{configs: []domain.ConfigBundle{
		{ID: "old", TenantID: "tenant-a", TargetID: "edge-a", Version: "v1", CreatedAt: now},
		{ID: "selected", TenantID: "tenant-a", TargetID: "edge-a", Version: "v2", CreatedAt: now.Add(time.Minute), Values: map[string]string{
			"endpoint": "edge.example.com:443",
			"region":   "jp",
			"healthy":  "true",
		}},
		{ID: "other", TenantID: "tenant-a", TargetID: "edge-b", Version: "v9", CreatedAt: now.Add(2 * time.Minute)},
	}}

	if err := svc.SyncOnce(context.Background(), client); err != nil {
		t.Fatalf("sync once: %v", err)
	}
	snapshot := svc.Snapshot()
	if snapshot.ConfigVersion != "v2" || snapshot.Endpoint != "edge.example.com:443" || snapshot.Region != "jp" || !snapshot.Healthy {
		t.Fatalf("unexpected snapshot after sync: %+v", snapshot)
	}
	if len(client.heartbeats) != 1 {
		t.Fatalf("expected one heartbeat, got %+v", client.heartbeats)
	}
	heartbeat := client.heartbeats[0]
	if heartbeat.NodeID != "edge-a" || heartbeat.Endpoint != "edge.example.com:443" || !heartbeat.Healthy {
		t.Fatalf("unexpected heartbeat: %+v", heartbeat)
	}
}

func TestSyncOncePushesHeartbeatWithoutConfig(t *testing.T) {
	svc := newTestService(t)
	client := &fakeSyncClient{configs: []domain.ConfigBundle{
		{ID: "other", TenantID: "tenant-a", TargetID: "edge-b", Version: "v1", CreatedAt: time.Now()},
	}}

	if err := svc.SyncOnce(context.Background(), client); err != nil {
		t.Fatalf("sync once: %v", err)
	}
	if len(client.heartbeats) != 1 {
		t.Fatalf("expected heartbeat without config, got %+v", client.heartbeats)
	}
	if svc.Snapshot().ConfigVersion != "bootstrap" {
		t.Fatalf("unexpected config version: %+v", svc.Snapshot())
	}
}

func TestWatchConfigOnceAppliesChangedConfigAndPushesHeartbeat(t *testing.T) {
	svc := newTestService(t)
	client := &fakeSyncClient{
		watchChanged: true,
		watchBundle: domain.ConfigBundle{
			ID:       "cfg-watch",
			TenantID: "tenant-a",
			TargetID: "edge-a",
			Version:  "watch-v2",
			Values: map[string]string{
				"endpoint": "watch.example.com:443",
				"healthy":  "true",
			},
		},
	}

	if err := svc.WatchConfigOnce(context.Background(), client, time.Second); err != nil {
		t.Fatalf("watch config once: %v", err)
	}
	if client.watchSince != "bootstrap" {
		t.Fatalf("expected bootstrap watch version, got %q", client.watchSince)
	}
	if got := svc.Snapshot(); got.ConfigVersion != "watch-v2" || got.Endpoint != "watch.example.com:443" || !got.Healthy {
		t.Fatalf("unexpected watched snapshot: %+v", got)
	}
	if len(client.heartbeats) != 1 || client.heartbeats[0].Endpoint != "watch.example.com:443" {
		t.Fatalf("expected watched heartbeat, got %+v", client.heartbeats)
	}
}

func TestSyncOnceReturnsConfigFetchErrorBeforeHeartbeat(t *testing.T) {
	svc := newTestService(t)
	client := &fakeSyncClient{configErr: errors.New("control unavailable")}

	if err := svc.SyncOnce(context.Background(), client); err == nil {
		t.Fatal("expected config fetch error")
	}
	if len(client.heartbeats) != 0 {
		t.Fatalf("heartbeat should not be pushed after config fetch error: %+v", client.heartbeats)
	}
}

func TestApplyConfigRejectsInvalidTargetAndHealthyValue(t *testing.T) {
	svc := newTestService(t)
	err := svc.ApplyConfig(domain.ConfigBundle{
		ID:       "bad-target",
		TenantID: "tenant-a",
		TargetID: "edge-b",
		Version:  "v1",
	})
	if err == nil {
		t.Fatal("expected target mismatch error")
	}
	err = svc.ApplyConfig(domain.ConfigBundle{
		ID:       "bad-healthy",
		TenantID: "tenant-a",
		TargetID: "edge-a",
		Version:  "v1",
		Values:   map[string]string{"healthy": "not-bool"},
	})
	if err == nil {
		t.Fatal("expected invalid healthy config to be rejected")
	}
}

func TestNewServiceRejectsUnsupportedRole(t *testing.T) {
	_, err := NewService(Snapshot{
		TenantID: "tenant-a",
		NodeID:   "edge-a",
		Role:     domain.NodeRole("database"),
		Region:   "hk",
	})
	if err == nil {
		t.Fatal("expected unsupported role to be rejected")
	}
}

func newTestService(t *testing.T) *Service {
	t.Helper()
	svc, err := NewService(Snapshot{
		TenantID:      "tenant-a",
		NodeID:        "edge-a",
		Role:          domain.NodeOverseasEdge,
		Region:        "hk",
		Endpoint:      "old.example.com:443",
		Healthy:       false,
		ConfigVersion: "bootstrap",
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

type fakeSyncClient struct {
	configs      []domain.ConfigBundle
	configErr    error
	heartbeatErr error
	heartbeats   []domain.NodeHeartbeat
	watchBundle  domain.ConfigBundle
	watchChanged bool
	watchErr     error
	watchSince   string
}

func (f *fakeSyncClient) Configs(ctx context.Context, tenantID string) ([]domain.ConfigBundle, error) {
	if f.configErr != nil {
		return nil, f.configErr
	}
	return append([]domain.ConfigBundle(nil), f.configs...), nil
}

func (f *fakeSyncClient) WatchConfig(ctx context.Context, tenantID, targetID, sinceVersion string, timeout time.Duration) (domain.ConfigBundle, bool, error) {
	f.watchSince = sinceVersion
	if f.watchErr != nil {
		return domain.ConfigBundle{}, false, f.watchErr
	}
	return f.watchBundle, f.watchChanged, nil
}

func (f *fakeSyncClient) PushNodeHeartbeat(ctx context.Context, tenantID string, heartbeat domain.NodeHeartbeat) (domain.Node, error) {
	if f.heartbeatErr != nil {
		return domain.Node{}, f.heartbeatErr
	}
	f.heartbeats = append(f.heartbeats, heartbeat)
	return domain.Node{
		ID:        heartbeat.NodeID,
		TenantID:  tenantID,
		Role:      domain.NodeOverseasEdge,
		Region:    "control-region",
		Endpoint:  heartbeat.Endpoint,
		Healthy:   heartbeat.Healthy,
		UpdatedAt: time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC),
	}, nil
}
