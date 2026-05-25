package agent

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	configsign "anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/telemetry"
)

func TestFileSigningKeyCacheRoundTrip(t *testing.T) {
	cache, err := NewFileSigningKeyCache(filepath.Join(t.TempDir(), "agent", "signing-key.json"))
	if err != nil {
		t.Fatalf("new signing key cache: %v", err)
	}
	if _, err := cache.Load(); !errors.Is(err, ErrSigningKeyCacheMiss) {
		t.Fatalf("expected signing key cache miss, got %v", err)
	}

	key := testSigningPublicKey(t)
	if err := cache.Save(key); err != nil {
		t.Fatalf("save signing key cache: %v", err)
	}
	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("load signing key cache: %v", err)
	}
	if loaded.PublicKey != key.PublicKey || loaded.Algorithm != key.Algorithm {
		t.Fatalf("unexpected loaded signing key: %+v", loaded)
	}
}

func TestSyncSignedOnceWithKeyRefreshUsesRotatedControlKey(t *testing.T) {
	svc, err := NewService(configsign.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	cache, err := NewFileSigningKeyCache(filepath.Join(t.TempDir(), "signing-key.json"))
	if err != nil {
		t.Fatalf("new signing key cache: %v", err)
	}
	oldKey := testSigningPublicKey(t)
	if err := cache.Save(oldKey); err != nil {
		t.Fatalf("seed signing key cache: %v", err)
	}
	signer, signed := testSignedBundle(t, "rotated-v1")
	key, err := configsign.NewSigningPublicKey(signer.PublicKey(), time.Date(2026, 5, 12, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new signing public key: %v", err)
	}
	client := &fakeSigningKeySyncClient{key: key, configs: []configsign.SignedBundle{signed}}

	if err := svc.SyncSignedOnceWithKeyRefresh(context.Background(), client, cache); err != nil {
		t.Fatalf("sync signed once with key refresh: %v", err)
	}
	if got := svc.Snapshot().ConfigVersion; got != "rotated-v1" {
		t.Fatalf("expected rotated-v1 config, got %s", got)
	}
	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("load refreshed signing key: %v", err)
	}
	if loaded.PublicKey != key.PublicKey {
		t.Fatal("expected refreshed signing key to be cached")
	}
}

func TestSyncSignedOnceWithKeyRefreshFallsBackToCachedKey(t *testing.T) {
	svc, err := NewService(configsign.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	cache, err := NewFileSigningKeyCache(filepath.Join(t.TempDir(), "signing-key.json"))
	if err != nil {
		t.Fatalf("new signing key cache: %v", err)
	}
	signer, signed := testSignedBundle(t, "cached-v1")
	key, err := configsign.NewSigningPublicKey(signer.PublicKey(), time.Date(2026, 5, 12, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new signing public key: %v", err)
	}
	if err := cache.Save(key); err != nil {
		t.Fatalf("seed signing key cache: %v", err)
	}
	client := &fakeSigningKeySyncClient{
		keyErr:  errors.New("control signing key endpoint unavailable"),
		configs: []configsign.SignedBundle{signed},
	}

	if err := svc.SyncSignedOnceWithKeyRefresh(context.Background(), client, cache); err != nil {
		t.Fatalf("sync signed once with cached key fallback: %v", err)
	}
	if got := svc.Snapshot().ConfigVersion; got != "cached-v1" {
		t.Fatalf("expected cached-v1 config, got %s", got)
	}
}

func TestSyncSignedOnceWithPinnedSigningKeyFallsBackToMatchingCache(t *testing.T) {
	svc, err := NewService(configsign.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	cache, err := NewFileSigningKeyCache(filepath.Join(t.TempDir(), "signing-key.json"))
	if err != nil {
		t.Fatalf("new signing key cache: %v", err)
	}
	signer, signed := testSignedBundle(t, "pinned-cache-v1")
	key, err := configsign.NewSigningPublicKey(signer.PublicKey(), time.Date(2026, 5, 12, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new signing public key: %v", err)
	}
	if err := cache.Save(key); err != nil {
		t.Fatalf("seed signing key cache: %v", err)
	}
	fingerprint, err := key.SHA256Fingerprint()
	if err != nil {
		t.Fatalf("fingerprint signing key: %v", err)
	}
	policy, err := NewSigningKeyTrustPolicy("sha256:" + strings.ToUpper(fingerprint))
	if err != nil {
		t.Fatalf("new signing key trust policy: %v", err)
	}
	client := &fakeSigningKeySyncClient{
		keyErr:  errors.New("control signing key endpoint unavailable"),
		configs: []configsign.SignedBundle{signed},
	}

	if err := svc.SyncSignedOnceWithKeyRefreshPolicy(context.Background(), client, cache, policy); err != nil {
		t.Fatalf("sync signed once with pinned cached key fallback: %v", err)
	}
	if got := svc.Snapshot().ConfigVersion; got != "pinned-cache-v1" {
		t.Fatalf("expected pinned-cache-v1 config, got %s", got)
	}
}

func TestSyncSignedOnceWithPinnedSigningKeyRejectsFetchedMismatch(t *testing.T) {
	svc, err := NewService(configsign.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	cache, err := NewFileSigningKeyCache(filepath.Join(t.TempDir(), "signing-key.json"))
	if err != nil {
		t.Fatalf("new signing key cache: %v", err)
	}
	cachedKey := testSigningPublicKey(t)
	if err := cache.Save(cachedKey); err != nil {
		t.Fatalf("seed signing key cache: %v", err)
	}
	pinned, err := cachedKey.SHA256Fingerprint()
	if err != nil {
		t.Fatalf("fingerprint cached key: %v", err)
	}
	policy, err := NewSigningKeyTrustPolicy(pinned)
	if err != nil {
		t.Fatalf("new signing key trust policy: %v", err)
	}
	newSigner, signed := testSignedBundle(t, "unpinned-v1")
	newKey, err := configsign.NewSigningPublicKey(newSigner.PublicKey(), time.Date(2026, 5, 12, 3, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new signing public key: %v", err)
	}
	client := &fakeSigningKeySyncClient{key: newKey, configs: []configsign.SignedBundle{signed}}

	err = svc.SyncSignedOnceWithKeyRefreshPolicy(context.Background(), client, cache, policy)
	if err == nil {
		t.Fatal("expected fetched key pin mismatch to fail")
	}
	if !strings.Contains(err.Error(), "pin") {
		t.Fatalf("expected pin mismatch error, got %v", err)
	}
	if got := svc.Snapshot().ConfigVersion; got != configsign.Default().Agent.ConfigVersion {
		t.Fatalf("expected config to remain unchanged, got %s", got)
	}
	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("load signing key cache: %v", err)
	}
	if loaded.PublicKey != cachedKey.PublicKey {
		t.Fatal("mismatched fetched key should not replace cached key")
	}
}

func TestSigningKeyTrustPolicyRejectsInvalidPin(t *testing.T) {
	if _, err := NewSigningKeyTrustPolicy("not-hex"); err == nil {
		t.Fatal("expected invalid signing key pin to fail")
	}
}

func TestSyncSignedOnceWithKeyRefreshDoesNotCacheUnverifiedKey(t *testing.T) {
	svc, err := NewService(configsign.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	cache, err := NewFileSigningKeyCache(filepath.Join(t.TempDir(), "signing-key.json"))
	if err != nil {
		t.Fatalf("new signing key cache: %v", err)
	}
	cachedKey := testSigningPublicKey(t)
	if err := cache.Save(cachedKey); err != nil {
		t.Fatalf("seed signing key cache: %v", err)
	}
	newSigner, newKeyBundle := testSignedBundle(t, "new-v1")
	newKey, err := configsign.NewSigningPublicKey(newSigner.PublicKey(), time.Date(2026, 5, 12, 3, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new signing public key: %v", err)
	}
	newKeyBundle.Bundle.Version = "tampered-v2"
	client := &fakeSigningKeySyncClient{key: newKey, configs: []configsign.SignedBundle{newKeyBundle}}

	if err := svc.SyncSignedOnceWithKeyRefresh(context.Background(), client, cache); err == nil {
		t.Fatal("expected tampered config to fail verification")
	}
	loaded, err := cache.Load()
	if err != nil {
		t.Fatalf("load signing key cache: %v", err)
	}
	if loaded.PublicKey != cachedKey.PublicKey {
		t.Fatal("unverified fetched key should not replace cached key")
	}
}

func testSigningPublicKey(t *testing.T) configsign.SigningPublicKey {
	t.Helper()
	signer, err := configsign.NewConfigSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	key, err := configsign.NewSigningPublicKey(signer.PublicKey(), time.Date(2026, 5, 12, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new signing public key: %v", err)
	}
	return key
}

func testSignedBundle(t *testing.T, version string) (*configsign.ConfigSigner, configsign.SignedBundle) {
	t.Helper()
	signer, err := configsign.NewConfigSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	signed, err := signer.Sign(domain.ConfigBundle{
		ID:        "cfg-" + version,
		TenantID:  "default",
		TargetID:  "local-dev",
		Version:   version,
		CreatedAt: time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC),
		Values:    map[string]string{"transport": "hysteria2"},
	}, time.Date(2026, 5, 12, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	return signer, signed
}

type fakeSigningKeySyncClient struct {
	key     configsign.SigningPublicKey
	keyErr  error
	configs []configsign.SignedBundle
	reports []telemetry.Report
}

func (f *fakeSigningKeySyncClient) ConfigSigningKey(ctx context.Context) (configsign.SigningPublicKey, error) {
	if f.keyErr != nil {
		return configsign.SigningPublicKey{}, f.keyErr
	}
	return f.key, nil
}

func (f *fakeSigningKeySyncClient) SignedConfigs(ctx context.Context, tenantID string) ([]configsign.SignedBundle, error) {
	return append([]configsign.SignedBundle(nil), f.configs...), nil
}

func (f *fakeSigningKeySyncClient) PushTelemetry(ctx context.Context, tenantID string, report telemetry.Report) (telemetry.Report, error) {
	f.reports = append(f.reports, report)
	return report, nil
}
