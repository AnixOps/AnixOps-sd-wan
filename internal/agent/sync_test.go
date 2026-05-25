package agent

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/telemetry"
)

func TestSyncOnceAppliesTargetConfigAndPushesTelemetry(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	client := &fakeSyncClient{configs: []domain.ConfigBundle{
		{
			ID:        "cfg-old",
			TenantID:  "default",
			TargetID:  "local-dev",
			Version:   "v1",
			CreatedAt: time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC),
		},
		{
			ID:        "cfg-new",
			TenantID:  "default",
			TargetID:  "local-dev",
			Version:   "v2",
			CreatedAt: time.Date(2026, 5, 12, 1, 0, 0, 0, time.UTC),
		},
	}}

	if err := svc.SyncOnce(context.Background(), client); err != nil {
		t.Fatalf("sync once: %v", err)
	}
	if got := svc.Snapshot().ConfigVersion; got != "v2" {
		t.Fatalf("expected config version v2, got %s", got)
	}
	if len(client.reports) != 1 {
		t.Fatalf("expected one telemetry report, got %d", len(client.reports))
	}
}

func TestSyncOnceReturnsConfigFetchError(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	client := &fakeSyncClient{configsErr: errors.New("control unavailable")}

	if err := svc.SyncOnce(context.Background(), client); err == nil {
		t.Fatal("expected config fetch error")
	}
}

func TestWatchConfigOnceAppliesChangedConfigAndPushesTelemetry(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	client := &fakeSyncClient{
		watchChanged: true,
		watchBundle: domain.ConfigBundle{
			ID:       "cfg-watch",
			TenantID: "default",
			TargetID: "local-dev",
			Version:  "watch-v2",
		},
	}

	if err := svc.WatchConfigOnce(context.Background(), client, time.Second); err != nil {
		t.Fatalf("watch config once: %v", err)
	}
	if client.watchSince != "dev" {
		t.Fatalf("expected watch since current dev config, got %q", client.watchSince)
	}
	if got := svc.Snapshot().ConfigVersion; got != "watch-v2" {
		t.Fatalf("expected watched config version, got %s", got)
	}
	if len(client.reports) != 1 {
		t.Fatalf("expected one telemetry report, got %d", len(client.reports))
	}
}

func TestSyncSignedOnceVerifiesBeforeApply(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	signer, err := config.NewConfigSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	signed, err := signer.Sign(domain.ConfigBundle{
		ID:        "cfg-signed",
		TenantID:  "default",
		TargetID:  "local-dev",
		Version:   "signed-v1",
		CreatedAt: time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC),
	}, time.Now())
	if err != nil {
		t.Fatalf("sign config: %v", err)
	}
	client := &fakeSignedSyncClient{configs: []config.SignedBundle{signed}}

	if err := svc.SyncSignedOnce(context.Background(), client, signer); err != nil {
		t.Fatalf("signed sync once: %v", err)
	}
	if got := svc.Snapshot().ConfigVersion; got != "signed-v1" {
		t.Fatalf("expected signed-v1, got %s", got)
	}
}

func TestSyncSignedOnceRejectsTamperedConfig(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	signer, err := config.NewConfigSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	signed, err := signer.Sign(domain.ConfigBundle{
		ID:       "cfg-signed",
		TenantID: "default",
		TargetID: "local-dev",
		Version:  "signed-v1",
	}, time.Now())
	if err != nil {
		t.Fatalf("sign config: %v", err)
	}
	signed.Bundle.Version = "tampered-v2"
	client := &fakeSignedSyncClient{configs: []config.SignedBundle{signed}}

	if err := svc.SyncSignedOnce(context.Background(), client, signer); err == nil {
		t.Fatal("expected tampered signed config to fail")
	}
	if got := svc.Snapshot().ConfigVersion; got == "tampered-v2" {
		t.Fatal("tampered config should not be applied")
	}
}

func TestWatchSignedConfigOnceVerifiesBeforeApply(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	signer, err := config.NewConfigSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	signed, err := signer.Sign(domain.ConfigBundle{
		ID:       "cfg-watch-signed",
		TenantID: "default",
		TargetID: "local-dev",
		Version:  "watch-signed-v2",
	}, time.Now())
	if err != nil {
		t.Fatalf("sign config: %v", err)
	}
	client := &fakeSignedSyncClient{watchBundle: signed, watchChanged: true}

	if err := svc.WatchSignedConfigOnce(context.Background(), client, signer, time.Second); err != nil {
		t.Fatalf("watch signed config once: %v", err)
	}
	if client.watchSince != "dev" {
		t.Fatalf("expected watch since dev, got %q", client.watchSince)
	}
	if got := svc.Snapshot().ConfigVersion; got != "watch-signed-v2" {
		t.Fatalf("expected watched signed config version, got %s", got)
	}
}

func TestRunSyncLoopRetriesAfterTransientError(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	client := &retrySyncClient{cancel: cancel}

	err = svc.RunSyncLoop(ctx, client, time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if client.configCalls < 2 {
		t.Fatalf("expected retry after transient error, got %d config calls", client.configCalls)
	}
	if got := svc.Snapshot().ConfigVersion; got != "v2" {
		t.Fatalf("expected config version v2 after retry, got %s", got)
	}
}

func TestSyncLoopBackoffOptions(t *testing.T) {
	options, err := normalizeSyncLoopOptions(SyncLoopOptions{Interval: time.Second})
	if err != nil {
		t.Fatalf("normalize default backoff: %v", err)
	}
	if options.InitialBackoff != time.Second || options.MaxBackoff != 8*time.Second {
		t.Fatalf("unexpected default backoff options: %+v", options)
	}
	if got := nextSyncBackoff(time.Second, 5*time.Second); got != 2*time.Second {
		t.Fatalf("expected doubled backoff, got %s", got)
	}
	if got := nextSyncBackoff(4*time.Second, 5*time.Second); got != 5*time.Second {
		t.Fatalf("expected capped backoff, got %s", got)
	}
}

func TestRunSyncLoopRejectsInvalidBackoffOptions(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	err = svc.RunSyncLoopWithOptions(context.Background(), &fakeSyncClient{}, SyncLoopOptions{
		Interval:       time.Millisecond,
		InitialBackoff: 2 * time.Millisecond,
		MaxBackoff:     time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected invalid backoff options to be rejected")
	}
}

func TestSyncOnceQueuesTelemetryOnPushFailureAndFlushesLater(t *testing.T) {
	queue, err := NewFileTelemetryQueue(filepath.Join(t.TempDir(), "telemetry-queue.json"))
	if err != nil {
		t.Fatalf("new telemetry queue: %v", err)
	}
	svc, err := NewServiceWithTelemetryQueue(config.Default(), nil, queue)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	client := &fakeSyncClient{pushErr: errors.New("control unavailable")}

	if err := svc.SyncOnce(context.Background(), client); err == nil {
		t.Fatal("expected telemetry push error")
	}
	queued, err := queue.Load()
	if err != nil {
		t.Fatalf("load queued telemetry: %v", err)
	}
	if len(queued) != 1 {
		t.Fatalf("expected one queued report, got %+v", queued)
	}
	if len(client.reports) != 0 {
		t.Fatalf("failed push should not be recorded as delivered, got %+v", client.reports)
	}

	client.pushErr = nil
	if err := svc.SyncOnce(context.Background(), client); err != nil {
		t.Fatalf("sync retry: %v", err)
	}
	if len(client.reports) != 2 {
		t.Fatalf("expected queued and current telemetry to be delivered, got %d reports", len(client.reports))
	}
	queued, err = queue.Load()
	if err != nil {
		t.Fatalf("load cleared queue: %v", err)
	}
	if len(queued) != 0 {
		t.Fatalf("expected telemetry queue to be cleared, got %+v", queued)
	}
}

type fakeSyncClient struct {
	configs      []domain.ConfigBundle
	configsErr   error
	pushErr      error
	reports      []telemetry.Report
	watchBundle  domain.ConfigBundle
	watchChanged bool
	watchErr     error
	watchSince   string
}

func (f *fakeSyncClient) Configs(ctx context.Context, tenantID string) ([]domain.ConfigBundle, error) {
	if f.configsErr != nil {
		return nil, f.configsErr
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

func (f *fakeSyncClient) PushTelemetry(ctx context.Context, tenantID string, report telemetry.Report) (telemetry.Report, error) {
	if f.pushErr != nil {
		return telemetry.Report{}, f.pushErr
	}
	f.reports = append(f.reports, report)
	return report, nil
}

type retrySyncClient struct {
	configCalls int
	cancel      context.CancelFunc
}

func (r *retrySyncClient) Configs(ctx context.Context, tenantID string) ([]domain.ConfigBundle, error) {
	r.configCalls++
	if r.configCalls == 1 {
		return nil, errors.New("temporary control outage")
	}
	r.cancel()
	return []domain.ConfigBundle{{
		ID:       "cfg-new",
		TenantID: tenantID,
		TargetID: "local-dev",
		Version:  "v2",
	}}, nil
}

func (r *retrySyncClient) PushTelemetry(ctx context.Context, tenantID string, report telemetry.Report) (telemetry.Report, error) {
	return report, nil
}

type fakeSignedSyncClient struct {
	configs      []config.SignedBundle
	reports      []telemetry.Report
	watchBundle  config.SignedBundle
	watchChanged bool
	watchErr     error
	watchSince   string
}

func (f *fakeSignedSyncClient) SignedConfigs(ctx context.Context, tenantID string) ([]config.SignedBundle, error) {
	return append([]config.SignedBundle(nil), f.configs...), nil
}

func (f *fakeSignedSyncClient) WatchSignedConfig(ctx context.Context, tenantID, targetID, sinceVersion string, timeout time.Duration) (config.SignedBundle, bool, error) {
	f.watchSince = sinceVersion
	if f.watchErr != nil {
		return config.SignedBundle{}, false, f.watchErr
	}
	return f.watchBundle, f.watchChanged, nil
}

func (f *fakeSignedSyncClient) PushTelemetry(ctx context.Context, tenantID string, report telemetry.Report) (telemetry.Report, error) {
	f.reports = append(f.reports, report)
	return report, nil
}
