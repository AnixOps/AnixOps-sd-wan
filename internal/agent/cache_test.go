package agent

import (
	"errors"
	"path/filepath"
	"testing"

	"anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/domain"
)

func TestFileConfigCacheRoundTrip(t *testing.T) {
	cache, err := NewFileConfigCache(filepath.Join(t.TempDir(), "agent", "config.json"))
	if err != nil {
		t.Fatalf("new cache: %v", err)
	}
	if _, err := cache.Load(); !errors.Is(err, ErrConfigCacheMiss) {
		t.Fatalf("expected cache miss, got %v", err)
	}

	bundle := domain.ConfigBundle{
		ID:       "cfg-1",
		TenantID: "default",
		TargetID: "local-dev",
		Version:  "v1",
		Values:   map[string]string{"transport": "wireguard"},
	}
	if err := cache.Save(bundle); err != nil {
		t.Fatalf("save cache: %v", err)
	}
	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("load cache: %v", err)
	}
	if loaded.Version != "v1" || loaded.Values["transport"] != "wireguard" {
		t.Fatalf("unexpected loaded bundle: %+v", loaded)
	}
}

func TestServiceRestoresAndPersistsCachedConfig(t *testing.T) {
	cache, err := NewFileConfigCache(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("new cache: %v", err)
	}
	if err := cache.Save(domain.ConfigBundle{
		ID:       "cfg-cached",
		TenantID: "default",
		TargetID: "local-dev",
		Version:  "cached-v1",
	}); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	svc, err := NewServiceWithCache(config.Default(), cache)
	if err != nil {
		t.Fatalf("new service with cache: %v", err)
	}
	if got := svc.Snapshot().ConfigVersion; got != "cached-v1" {
		t.Fatalf("expected cached-v1 snapshot, got %s", got)
	}

	if err := svc.ApplyConfig(domain.ConfigBundle{
		ID:       "cfg-new",
		TenantID: "default",
		TargetID: "local-dev",
		Version:  "cached-v2",
	}); err != nil {
		t.Fatalf("apply config: %v", err)
	}
	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("reload cache: %v", err)
	}
	if loaded.Version != "cached-v2" {
		t.Fatalf("expected persisted cached-v2, got %+v", loaded)
	}
}
