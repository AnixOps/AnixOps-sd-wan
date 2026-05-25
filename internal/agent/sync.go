package agent

import (
	"context"
	"fmt"
	"time"

	"anixops-sd-wan/internal/cert"
	configsign "anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/telemetry"
)

type ControlSyncClient interface {
	Configs(ctx context.Context, tenantID string) ([]domain.ConfigBundle, error)
	PushTelemetry(ctx context.Context, tenantID string, report telemetry.Report) (telemetry.Report, error)
}

type ConfigWatchClient interface {
	WatchConfig(ctx context.Context, tenantID, targetID, sinceVersion string, timeout time.Duration) (domain.ConfigBundle, bool, error)
	PushTelemetry(ctx context.Context, tenantID string, report telemetry.Report) (telemetry.Report, error)
}

type SignedControlSyncClient interface {
	SignedConfigs(ctx context.Context, tenantID string) ([]configsign.SignedBundle, error)
	PushTelemetry(ctx context.Context, tenantID string, report telemetry.Report) (telemetry.Report, error)
}

type SignedConfigWatchClient interface {
	WatchSignedConfig(ctx context.Context, tenantID, targetID, sinceVersion string, timeout time.Duration) (configsign.SignedBundle, bool, error)
	PushTelemetry(ctx context.Context, tenantID string, report telemetry.Report) (telemetry.Report, error)
}

type SigningKeySyncClient interface {
	ConfigSigningKey(ctx context.Context) (configsign.SigningPublicKey, error)
	SignedConfigs(ctx context.Context, tenantID string) ([]configsign.SignedBundle, error)
	PushTelemetry(ctx context.Context, tenantID string, report telemetry.Report) (telemetry.Report, error)
}

type CRLClient interface {
	CertificateRevocationList(ctx context.Context, tenantID string) (cert.RevocationList, error)
}

type telemetryPusher interface {
	PushTelemetry(ctx context.Context, tenantID string, report telemetry.Report) (telemetry.Report, error)
}

type ConfigVerifier interface {
	Verify(configsign.SignedBundle) error
}

type SyncLoopOptions struct {
	Interval       time.Duration
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

func (s *Service) SyncOnce(ctx context.Context, client ControlSyncClient) error {
	if client == nil {
		return fmt.Errorf("control sync client is required")
	}

	snapshot := s.Snapshot()
	configs, err := client.Configs(ctx, snapshot.TenantID)
	if err != nil {
		return fmt.Errorf("fetch configs: %w", err)
	}
	if selected, ok := selectConfig(configs, snapshot.DeviceID); ok {
		if err := s.ApplyConfig(selected); err != nil {
			return fmt.Errorf("apply config: %w", err)
		}
	}

	report := s.TelemetryReport()
	if err := s.pushTelemetry(ctx, client, report); err != nil {
		return err
	}
	return nil
}

func (s *Service) WatchConfigOnce(ctx context.Context, client ConfigWatchClient, timeout time.Duration) error {
	if client == nil {
		return fmt.Errorf("config watch client is required")
	}
	snapshot := s.Snapshot()
	bundle, changed, err := client.WatchConfig(ctx, snapshot.TenantID, snapshot.DeviceID, snapshot.ConfigVersion, timeout)
	if err != nil {
		return fmt.Errorf("watch config: %w", err)
	}
	if changed {
		if err := s.ApplyConfig(bundle); err != nil {
			return fmt.Errorf("apply watched config: %w", err)
		}
	}
	report := s.TelemetryReport()
	if err := s.pushTelemetry(ctx, client, report); err != nil {
		return err
	}
	return nil
}

func (s *Service) WatchSignedConfigOnce(ctx context.Context, client SignedConfigWatchClient, verifier ConfigVerifier, timeout time.Duration) error {
	if client == nil {
		return fmt.Errorf("signed config watch client is required")
	}
	if verifier == nil {
		return fmt.Errorf("config verifier is required")
	}
	snapshot := s.Snapshot()
	signed, changed, err := client.WatchSignedConfig(ctx, snapshot.TenantID, snapshot.DeviceID, snapshot.ConfigVersion, timeout)
	if err != nil {
		return fmt.Errorf("watch signed config: %w", err)
	}
	if changed {
		if err := verifier.Verify(signed); err != nil {
			return fmt.Errorf("verify watched config: %w", err)
		}
		if err := s.ApplyConfig(signed.Bundle); err != nil {
			return fmt.Errorf("apply watched config: %w", err)
		}
	}
	report := s.TelemetryReport()
	if err := s.pushTelemetry(ctx, client, report); err != nil {
		return err
	}
	return nil
}

func (s *Service) SyncSignedOnce(ctx context.Context, client SignedControlSyncClient, verifier ConfigVerifier) error {
	if client == nil {
		return fmt.Errorf("signed control sync client is required")
	}
	if verifier == nil {
		return fmt.Errorf("config verifier is required")
	}

	snapshot := s.Snapshot()
	configs, err := client.SignedConfigs(ctx, snapshot.TenantID)
	if err != nil {
		return fmt.Errorf("fetch signed configs: %w", err)
	}
	if selected, ok, err := selectVerifiedConfig(configs, snapshot.DeviceID, verifier); err != nil {
		return fmt.Errorf("verify config: %w", err)
	} else if ok {
		if err := s.ApplyConfig(selected); err != nil {
			return fmt.Errorf("apply config: %w", err)
		}
	}

	report := s.TelemetryReport()
	if err := s.pushTelemetry(ctx, client, report); err != nil {
		return err
	}
	return nil
}

func (s *Service) SyncSignedOnceWithKeyRefresh(ctx context.Context, client SigningKeySyncClient, cache SigningKeyCache) error {
	return s.SyncSignedOnceWithKeyRefreshPolicy(ctx, client, cache, SigningKeyTrustPolicy{})
}

func (s *Service) SyncSignedOnceWithKeyRefreshPolicy(ctx context.Context, client SigningKeySyncClient, cache SigningKeyCache, trustPolicy SigningKeyTrustPolicy) error {
	if client == nil {
		return fmt.Errorf("signing key sync client is required")
	}

	key, fetched, err := signingKeyForSync(ctx, client, cache, trustPolicy)
	if err != nil {
		return err
	}
	verifier, err := configsign.NewConfigVerifierFromSigningKey(key)
	if err != nil {
		return fmt.Errorf("build config verifier from signing key: %w", err)
	}

	snapshot := s.Snapshot()
	configs, err := client.SignedConfigs(ctx, snapshot.TenantID)
	if err != nil {
		return fmt.Errorf("fetch signed configs: %w", err)
	}
	if selected, ok, err := selectVerifiedConfig(configs, snapshot.DeviceID, verifier); err != nil {
		return fmt.Errorf("verify config: %w", err)
	} else if ok {
		if err := s.ApplyConfig(selected); err != nil {
			return fmt.Errorf("apply config: %w", err)
		}
	}
	if fetched && cache != nil {
		if err := cache.Save(key); err != nil {
			return fmt.Errorf("save config signing key: %w", err)
		}
	}

	report := s.TelemetryReport()
	if err := s.pushTelemetry(ctx, client, report); err != nil {
		return err
	}
	return nil
}

func (s *Service) SyncCRLOnce(ctx context.Context, client CRLClient, cache CRLCache) error {
	if client == nil {
		return fmt.Errorf("crl client is required")
	}
	if cache == nil {
		return fmt.Errorf("crl cache is required")
	}

	snapshot := s.Snapshot()
	list, err := client.CertificateRevocationList(ctx, snapshot.TenantID)
	if err != nil {
		return fmt.Errorf("fetch certificate revocation list: %w", err)
	}
	if list.TenantID != snapshot.TenantID {
		return fmt.Errorf("crl tenant %q does not match agent tenant %q", list.TenantID, snapshot.TenantID)
	}
	if err := cache.Save(list); err != nil {
		return fmt.Errorf("save certificate revocation list: %w", err)
	}
	return nil
}

func (s *Service) pushTelemetry(ctx context.Context, client telemetryPusher, report telemetry.Report) error {
	report = report.Sanitized()
	pending := []telemetry.Report{report}
	if s.telemetryQueue != nil {
		queued, err := s.telemetryQueue.Load()
		if err != nil {
			return fmt.Errorf("load telemetry queue: %w", err)
		}
		pending = append(queued, report)
	}

	for index, queued := range pending {
		if _, err := client.PushTelemetry(ctx, queued.TenantID, queued); err != nil {
			if s.telemetryQueue != nil {
				if saveErr := s.telemetryQueue.Save(pending[index:]); saveErr != nil {
					return fmt.Errorf("push telemetry: %w; save telemetry queue: %v", err, saveErr)
				}
			}
			return fmt.Errorf("push telemetry: %w", err)
		}
	}
	if s.telemetryQueue != nil {
		if err := s.telemetryQueue.Save(nil); err != nil {
			return fmt.Errorf("clear telemetry queue: %w", err)
		}
	}
	return nil
}

func (s *Service) RunSyncLoop(ctx context.Context, client ControlSyncClient, interval time.Duration) error {
	return s.RunSyncLoopWithOptions(ctx, client, SyncLoopOptions{Interval: interval})
}

func (s *Service) RunSyncLoopWithOptions(ctx context.Context, client ControlSyncClient, options SyncLoopOptions) error {
	if client == nil {
		return fmt.Errorf("control sync client is required")
	}
	return runSyncLoop(ctx, options, func() error {
		return s.SyncOnce(ctx, client)
	})
}

func (s *Service) RunSignedSyncLoop(ctx context.Context, client SignedControlSyncClient, verifier ConfigVerifier, interval time.Duration) error {
	return s.RunSignedSyncLoopWithOptions(ctx, client, verifier, SyncLoopOptions{Interval: interval})
}

func (s *Service) RunSignedSyncLoopWithOptions(ctx context.Context, client SignedControlSyncClient, verifier ConfigVerifier, options SyncLoopOptions) error {
	if client == nil {
		return fmt.Errorf("signed control sync client is required")
	}
	if verifier == nil {
		return fmt.Errorf("config verifier is required")
	}
	return runSyncLoop(ctx, options, func() error {
		return s.SyncSignedOnce(ctx, client, verifier)
	})
}

func (s *Service) RunSignedKeySyncLoop(ctx context.Context, client SigningKeySyncClient, cache SigningKeyCache, interval time.Duration) error {
	return s.RunSignedKeySyncLoopWithOptions(ctx, client, cache, SyncLoopOptions{Interval: interval})
}

func (s *Service) RunSignedKeySyncLoopWithOptions(ctx context.Context, client SigningKeySyncClient, cache SigningKeyCache, options SyncLoopOptions) error {
	return s.RunSignedKeySyncLoopWithPolicyAndOptions(ctx, client, cache, SigningKeyTrustPolicy{}, options)
}

func (s *Service) RunSignedKeySyncLoopWithPolicy(ctx context.Context, client SigningKeySyncClient, cache SigningKeyCache, trustPolicy SigningKeyTrustPolicy, interval time.Duration) error {
	return s.RunSignedKeySyncLoopWithPolicyAndOptions(ctx, client, cache, trustPolicy, SyncLoopOptions{Interval: interval})
}

func (s *Service) RunSignedKeySyncLoopWithPolicyAndOptions(ctx context.Context, client SigningKeySyncClient, cache SigningKeyCache, trustPolicy SigningKeyTrustPolicy, options SyncLoopOptions) error {
	if client == nil {
		return fmt.Errorf("signing key sync client is required")
	}
	return runSyncLoop(ctx, options, func() error {
		return s.SyncSignedOnceWithKeyRefreshPolicy(ctx, client, cache, trustPolicy)
	})
}

func (s *Service) RunCRLSyncLoop(ctx context.Context, client CRLClient, cache CRLCache, interval time.Duration) error {
	return s.RunCRLSyncLoopWithOptions(ctx, client, cache, SyncLoopOptions{Interval: interval})
}

func (s *Service) RunCRLSyncLoopWithOptions(ctx context.Context, client CRLClient, cache CRLCache, options SyncLoopOptions) error {
	if client == nil {
		return fmt.Errorf("crl client is required")
	}
	if cache == nil {
		return fmt.Errorf("crl cache is required")
	}
	return runSyncLoop(ctx, options, func() error {
		return s.SyncCRLOnce(ctx, client, cache)
	})
}

func runSyncLoop(ctx context.Context, options SyncLoopOptions, syncOnce func() error) error {
	options, err := normalizeSyncLoopOptions(options)
	if err != nil {
		return err
	}

	backoff := options.InitialBackoff
	for {
		delay := options.Interval
		if err := syncOnce(); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			delay = backoff
			backoff = nextSyncBackoff(backoff, options.MaxBackoff)
		} else {
			backoff = options.InitialBackoff
		}

		timer := time.NewTimer(delay)
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

func normalizeSyncLoopOptions(options SyncLoopOptions) (SyncLoopOptions, error) {
	if options.Interval <= 0 {
		return SyncLoopOptions{}, fmt.Errorf("sync interval must be positive")
	}
	if options.InitialBackoff <= 0 {
		options.InitialBackoff = options.Interval
	}
	if options.MaxBackoff <= 0 {
		options.MaxBackoff = options.InitialBackoff * 8
	}
	if options.MaxBackoff < options.InitialBackoff {
		return SyncLoopOptions{}, fmt.Errorf("sync max backoff must be greater than or equal to initial backoff")
	}
	return options, nil
}

func nextSyncBackoff(current, max time.Duration) time.Duration {
	if current <= 0 {
		return max
	}
	next := current * 2
	if next < current || next > max {
		return max
	}
	return next
}

func signingKeyForSync(ctx context.Context, client SigningKeySyncClient, cache SigningKeyCache, trustPolicy SigningKeyTrustPolicy) (configsign.SigningPublicKey, bool, error) {
	key, err := client.ConfigSigningKey(ctx)
	if err == nil {
		if _, verifyErr := configsign.NewConfigVerifierFromSigningKey(key); verifyErr != nil {
			return configsign.SigningPublicKey{}, false, fmt.Errorf("validate fetched config signing key: %w", verifyErr)
		}
		if pinErr := trustPolicy.Validate(key); pinErr != nil {
			return configsign.SigningPublicKey{}, false, fmt.Errorf("validate fetched config signing key pin: %w", pinErr)
		}
		return key, true, nil
	}
	if cache == nil {
		return configsign.SigningPublicKey{}, false, fmt.Errorf("fetch config signing key: %w", err)
	}
	cached, cacheErr := cache.Load()
	if cacheErr != nil {
		return configsign.SigningPublicKey{}, false, fmt.Errorf("fetch config signing key: %w; load cached signing key: %v", err, cacheErr)
	}
	if pinErr := trustPolicy.Validate(cached); pinErr != nil {
		return configsign.SigningPublicKey{}, false, fmt.Errorf("validate cached config signing key pin: %w", pinErr)
	}
	return cached, false, nil
}

func selectConfig(configs []domain.ConfigBundle, deviceID string) (domain.ConfigBundle, bool) {
	var selected domain.ConfigBundle
	found := false
	for _, candidate := range configs {
		if candidate.TargetID != deviceID {
			continue
		}
		if !found || candidate.CreatedAt.After(selected.CreatedAt) || candidate.Version > selected.Version {
			selected = candidate
			found = true
		}
	}
	return selected, found
}

func selectVerifiedConfig(configs []configsign.SignedBundle, deviceID string, verifier ConfigVerifier) (domain.ConfigBundle, bool, error) {
	var selected domain.ConfigBundle
	found := false
	for _, candidate := range configs {
		if candidate.Bundle.TargetID != deviceID {
			continue
		}
		if err := verifier.Verify(candidate); err != nil {
			return domain.ConfigBundle{}, false, err
		}
		if !found || candidate.Bundle.CreatedAt.After(selected.CreatedAt) || candidate.Bundle.Version > selected.Version {
			selected = candidate.Bundle
			found = true
		}
	}
	return selected, found, nil
}
