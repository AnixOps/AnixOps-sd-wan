package agent

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"anixops-sd-wan/internal/cert"
	"anixops-sd-wan/internal/config"
)

func TestFileCRLCacheRoundTrip(t *testing.T) {
	cache, err := NewFileCRLCache(filepath.Join(t.TempDir(), "agent", "crl.json"))
	if err != nil {
		t.Fatalf("new crl cache: %v", err)
	}
	if _, err := cache.Load(); !errors.Is(err, ErrCRLCacheMiss) {
		t.Fatalf("expected crl cache miss, got %v", err)
	}

	list := testRevocationList(t, "tenant-a")
	if err := cache.Save(list); err != nil {
		t.Fatalf("save crl cache: %v", err)
	}
	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("load crl cache: %v", err)
	}
	if loaded.TenantID != "tenant-a" || len(loaded.CRLPEM) == 0 || len(loaded.Records) != 1 {
		t.Fatalf("unexpected loaded crl: %+v", loaded)
	}
}

func TestServiceSyncCRLOnceCachesTenantList(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	cache, err := NewFileCRLCache(filepath.Join(t.TempDir(), "crl.json"))
	if err != nil {
		t.Fatalf("new crl cache: %v", err)
	}
	client := &fakeCRLClient{list: testRevocationList(t, "default")}

	if err := svc.SyncCRLOnce(context.Background(), client, cache); err != nil {
		t.Fatalf("sync crl once: %v", err)
	}
	if len(client.tenants) != 1 || client.tenants[0] != "default" {
		t.Fatalf("expected default tenant crl request, got %+v", client.tenants)
	}
	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("load synced crl: %v", err)
	}
	if loaded.TenantID != "default" || len(loaded.CRLPEM) == 0 {
		t.Fatalf("unexpected synced crl: %+v", loaded)
	}
}

func TestServiceSyncCRLOnceRejectsTenantMismatch(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	cache, err := NewFileCRLCache(filepath.Join(t.TempDir(), "crl.json"))
	if err != nil {
		t.Fatalf("new crl cache: %v", err)
	}
	client := &fakeCRLClient{list: testRevocationList(t, "tenant-b")}

	if err := svc.SyncCRLOnce(context.Background(), client, cache); err == nil {
		t.Fatal("expected tenant mismatch to be rejected")
	}
	if _, err := cache.Load(); !errors.Is(err, ErrCRLCacheMiss) {
		t.Fatalf("tenant mismatch should not update cache, got %v", err)
	}
}

func TestRunCRLSyncLoopRetriesAfterTransientError(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	cache, err := NewFileCRLCache(filepath.Join(t.TempDir(), "crl.json"))
	if err != nil {
		t.Fatalf("new crl cache: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	client := &retryCRLClient{
		cancel: cancel,
		list:   testRevocationList(t, "default"),
	}

	err = svc.RunCRLSyncLoop(ctx, client, cache, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if client.calls < 2 {
		t.Fatalf("expected crl retry, got %d calls", client.calls)
	}
	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("load crl after retry: %v", err)
	}
	if loaded.TenantID != "default" {
		t.Fatalf("unexpected crl after retry: %+v", loaded)
	}
}

func testRevocationList(t *testing.T, tenantID string) cert.RevocationList {
	t.Helper()

	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := cert.NewAuthority("AnixOps Test CA", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	issued, err := authority.Issue(cert.Identity{TenantID: tenantID, DeviceID: "agent-a", Role: "agent"}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	if _, err := authority.Revoke(issued.Record.Serial, now.Add(time.Minute)); err != nil {
		t.Fatalf("revoke certificate: %v", err)
	}
	list, err := authority.RevocationListByTenant(tenantID, now.Add(2*time.Minute), time.Hour)
	if err != nil {
		t.Fatalf("revocation list: %v", err)
	}
	return list
}

type fakeCRLClient struct {
	list    cert.RevocationList
	err     error
	tenants []string
}

func (f *fakeCRLClient) CertificateRevocationList(ctx context.Context, tenantID string) (cert.RevocationList, error) {
	f.tenants = append(f.tenants, tenantID)
	if f.err != nil {
		return cert.RevocationList{}, f.err
	}
	return f.list, nil
}

type retryCRLClient struct {
	calls  int
	cancel context.CancelFunc
	list   cert.RevocationList
}

func (r *retryCRLClient) CertificateRevocationList(ctx context.Context, tenantID string) (cert.RevocationList, error) {
	r.calls++
	if r.calls == 1 {
		return cert.RevocationList{}, errors.New("temporary crl outage")
	}
	r.cancel()
	return r.list, nil
}
