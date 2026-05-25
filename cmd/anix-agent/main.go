package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"anixops-sd-wan/internal/agent"
	"anixops-sd-wan/internal/auth"
	"anixops-sd-wan/internal/buildinfo"
	"anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/controlclient"
	"anixops-sd-wan/internal/transport"
)

func main() {
	defaults := config.Default()
	once := flag.Bool("once", false, "print one agent snapshot and exit")
	syncOnce := flag.Bool("sync-once", false, "fetch control-plane config, push telemetry once, print snapshot and exit")
	controlURL := flag.String("control-url", "", "control plane base URL for config and telemetry sync")
	syncInterval := flag.Duration("sync-interval", 30*time.Second, "control plane sync interval")
	localAPIAddr := flag.String("local-api-addr", "", "local agent HTTP API listen address, disabled when empty")
	enableTransportRuntime := flag.Bool("transport-runtime", false, "enable local transport supervisor runtime")
	transportActive := flag.String("transport-active", string(transport.ProtocolHysteria2), "initial transport protocol when --transport-runtime is enabled")
	transportConfigDir := flag.String("transport-config-dir", "/etc/anixops", "transport protocol config directory when --transport-runtime is enabled")
	transportSwitchCooldown := flag.Duration("transport-switch-cooldown", 30*time.Second, "minimum interval between transport switches")
	tenantID := flag.String("tenant-id", defaults.Agent.TenantID, "agent tenant id")
	deviceID := flag.String("device-id", defaults.Agent.DeviceID, "agent device id")
	configVersion := flag.String("config-version", defaults.Agent.ConfigVersion, "initial local config version")
	cacheFile := flag.String("cache-file", "", "local agent config cache file")
	telemetryQueueFile := flag.String("telemetry-queue-file", "", "durable telemetry retry queue file")
	telemetryQueueMaxReports := flag.Int("telemetry-queue-max-reports", agent.DefaultTelemetryQueueMaxReports, "maximum durable telemetry reports to retain")
	crlCacheFile := flag.String("crl-cache-file", "", "local certificate revocation list cache file")
	crlSyncInterval := flag.Duration("crl-sync-interval", 5*time.Minute, "certificate revocation list sync interval")
	configSigningPublicKey := flag.String("config-signing-public-key", "", "base64 Ed25519 public key for signed config verification")
	configSigningKeyCacheFile := flag.String("config-signing-key-cache-file", "", "local config signing public key cache file for automatic key refresh")
	configSigningKeySHA256 := flag.String("config-signing-key-sha256", "", "optional SHA-256 hex pin for fetched or cached config signing public key")
	configSigningKeyApprovalFile := flag.String("config-signing-key-approval-file", "", "offline-approved config signing public key approval JSON file")
	configSigningKeyApprovalRequestFile := flag.String("config-signing-key-approval-request-file", "", "control-plane config signing key approval request JSON file to approve and exit")
	configSigningKeyApprovedBy := flag.String("config-signing-key-approved-by", "", "operator id recorded when approving a config signing key request")
	configSigningKeyApprovalNote := flag.String("config-signing-key-approval-note", "", "optional note recorded in a generated config signing key approval JSON file")
	actorID := flag.String("actor-id", "", "control plane actor id; defaults to device id")
	roles := flag.String("roles", string(auth.RoleAgent), "comma-separated control plane roles")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	info := buildinfo.Current("anix-agent")
	if *showVersion {
		fmt.Printf("%s %s %s %s\n", info.Name, info.Version, info.Commit, info.Date)
		return
	}
	if *once && *syncOnce {
		fmt.Fprintln(os.Stderr, "--once and --sync-once cannot be used together")
		os.Exit(2)
	}
	if *configSigningKeyApprovalRequestFile != "" {
		if *once || *syncOnce {
			fmt.Fprintln(os.Stderr, "--config-signing-key-approval-request-file cannot be combined with --once or --sync-once")
			os.Exit(2)
		}
		approval, err := approveConfigSigningKeyRequestFile(*configSigningKeyApprovalRequestFile, *configSigningKeyApprovalFile, *configSigningKeyApprovedBy, *configSigningKeyApprovalNote, time.Now().UTC())
		if err != nil {
			fmt.Fprintf(os.Stderr, "approve config signing key request: %v\n", err)
			os.Exit(2)
		}
		encode(approval)
		return
	}

	cfg := defaults
	cfg.Agent.TenantID = *tenantID
	cfg.Agent.DeviceID = *deviceID
	cfg.Agent.ConfigVersion = *configVersion
	var cache agent.ConfigCache
	var err error
	if *cacheFile != "" {
		cache, err = agent.NewFileConfigCache(*cacheFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent cache error: %v\n", err)
			os.Exit(1)
		}
	}
	var telemetryQueue agent.TelemetryQueue
	if *telemetryQueueFile != "" {
		telemetryQueue, err = agent.NewBoundedFileTelemetryQueue(*telemetryQueueFile, *telemetryQueueMaxReports)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent telemetry queue error: %v\n", err)
			os.Exit(1)
		}
	}
	var crlCache agent.CRLCache
	if *crlCacheFile != "" {
		crlCache, err = agent.NewFileCRLCache(*crlCacheFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent crl cache error: %v\n", err)
			os.Exit(1)
		}
	}
	var signingKeyCache agent.SigningKeyCache
	if *configSigningKeyCacheFile != "" {
		signingKeyCache, err = agent.NewFileSigningKeyCache(*configSigningKeyCacheFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent signing key cache error: %v\n", err)
			os.Exit(1)
		}
	}
	signingKeyTrustPolicy, err := agent.NewSigningKeyTrustPolicy(*configSigningKeySHA256)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent signing key pin error: %v\n", err)
		os.Exit(2)
	}
	if signingKeyTrustPolicy.PinnedSHA256 != "" && signingKeyCache == nil {
		fmt.Fprintln(os.Stderr, "--config-signing-key-sha256 requires --config-signing-key-cache-file")
		os.Exit(2)
	}
	if *configSigningKeyApprovalFile != "" {
		approval, err := agent.LoadSigningKeyApproval(*configSigningKeyApprovalFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent signing key approval error: %v\n", err)
			os.Exit(2)
		}
		approvalPolicy, err := approval.TrustPolicy()
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent signing key approval error: %v\n", err)
			os.Exit(2)
		}
		if signingKeyTrustPolicy.PinnedSHA256 != "" && signingKeyTrustPolicy.PinnedSHA256 != approvalPolicy.PinnedSHA256 {
			fmt.Fprintln(os.Stderr, "--config-signing-key-sha256 does not match --config-signing-key-approval-file")
			os.Exit(2)
		}
		signingKeyTrustPolicy = approvalPolicy
	}
	if signingKeyTrustPolicy.PinnedSHA256 != "" && signingKeyCache == nil {
		fmt.Fprintln(os.Stderr, "config signing key pinning requires --config-signing-key-cache-file")
		os.Exit(2)
	}
	service, err := newAgentService(cfg, cache, telemetryQueue, *enableTransportRuntime, *transportActive, *transportSwitchCooldown, *transportConfigDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent config error: %v\n", err)
		os.Exit(1)
	}

	if *once {
		encode(service.Snapshot())
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *syncOnce {
		client := mustControlClient(*controlURL, *tenantID, *deviceID, *actorID, *roles)
		verifier := mustConfigVerifier(*configSigningPublicKey)
		if verifier != nil {
			err = service.SyncSignedOnce(ctx, client, verifier)
		} else if signingKeyCache != nil {
			err = service.SyncSignedOnceWithKeyRefreshPolicy(ctx, client, signingKeyCache, signingKeyTrustPolicy)
		} else {
			err = service.SyncOnce(ctx, client)
		}
		if err == nil && crlCache != nil {
			err = service.SyncCRLOnce(ctx, client, crlCache)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "agent sync error: %v\n", err)
			os.Exit(1)
		}
		encode(service.Snapshot())
		return
	}

	fmt.Fprintln(os.Stderr, "anix-agent starting")
	if *controlURL == "" {
		if crlCache != nil {
			fmt.Fprintln(os.Stderr, "--crl-cache-file requires --control-url")
			os.Exit(2)
		}
		if signingKeyCache != nil {
			fmt.Fprintln(os.Stderr, "--config-signing-key-cache-file requires --control-url")
			os.Exit(2)
		}
		errCh := make(chan error, 2)
		go func() { errCh <- service.Start(ctx) }()
		if *localAPIAddr != "" {
			go func() { errCh <- service.RunLocalAPI(ctx, *localAPIAddr) }()
		}
		err = <-errCh
		stop()
		if err != nil && err != context.Canceled {
			fmt.Fprintf(os.Stderr, "agent stopped with error: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "anix-agent stopped")
		return
	}

	client := mustControlClient(*controlURL, *tenantID, *deviceID, *actorID, *roles)
	verifier := mustConfigVerifier(*configSigningPublicKey)
	errCh := make(chan error, 4)
	go func() { errCh <- service.Start(ctx) }()
	if *localAPIAddr != "" {
		go func() { errCh <- service.RunLocalAPI(ctx, *localAPIAddr) }()
	}
	go func() {
		if verifier != nil {
			errCh <- service.RunSignedSyncLoop(ctx, client, verifier, *syncInterval)
			return
		}
		if signingKeyCache != nil {
			errCh <- service.RunSignedKeySyncLoopWithPolicy(ctx, client, signingKeyCache, signingKeyTrustPolicy, *syncInterval)
			return
		}
		errCh <- service.RunSyncLoop(ctx, client, *syncInterval)
	}()
	if crlCache != nil {
		go func() {
			errCh <- service.RunCRLSyncLoop(ctx, client, crlCache, *crlSyncInterval)
		}()
	}

	err = <-errCh
	stop()
	if err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "agent stopped with error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "anix-agent stopped")
}

func encode(value interface{}) {
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		fmt.Fprintf(os.Stderr, "encode output: %v\n", err)
		os.Exit(1)
	}
}

func approveConfigSigningKeyRequestFile(requestPath, approvalPath, approvedBy, note string, approvedAt time.Time) (agent.SigningKeyApproval, error) {
	if strings.TrimSpace(approvalPath) == "" {
		return agent.SigningKeyApproval{}, fmt.Errorf("--config-signing-key-approval-file is required when approving a signing key request")
	}
	request, err := config.LoadSigningKeyApprovalRequest(requestPath)
	if err != nil {
		return agent.SigningKeyApproval{}, err
	}
	approval, err := agent.NewSigningKeyApprovalFromRequest(request, approvedBy, approvedAt)
	if err != nil {
		return agent.SigningKeyApproval{}, err
	}
	if strings.TrimSpace(note) != "" {
		approval.Note = strings.TrimSpace(note)
	}
	if err := agent.SaveSigningKeyApproval(approvalPath, approval); err != nil {
		return agent.SigningKeyApproval{}, err
	}
	return approval, nil
}

func newAgentService(cfg config.Config, cache agent.ConfigCache, telemetryQueue agent.TelemetryQueue, enableTransportRuntime bool, active string, cooldown time.Duration, configDir string) (*agent.Service, error) {
	if !enableTransportRuntime {
		return agent.NewServiceWithTelemetryQueue(cfg, cache, telemetryQueue)
	}
	runtime, err := transport.NewSwitchRuntime(transport.Protocol(strings.TrimSpace(active)), cooldown, nil)
	if err != nil {
		return nil, err
	}
	supervisor, err := transport.NewSupervisor(nil, nil, transport.DefaultLifecycleSpecs(configDir))
	if err != nil {
		return nil, err
	}
	return agent.NewServiceWithTransportRuntimeAndTelemetryQueue(cfg, cache, runtime, supervisor.Activate, telemetryQueue)
}

func mustControlClient(baseURL, tenantID, deviceID, actorID, roles string) *controlclient.Client {
	if baseURL == "" {
		fmt.Fprintln(os.Stderr, "control url is required for sync")
		os.Exit(2)
	}
	if actorID == "" {
		actorID = deviceID
	}
	client, err := controlclient.NewWithCredentials(baseURL, nil, controlclient.Credentials{
		TenantID: tenantID,
		ActorID:  actorID,
		Roles:    parseRoles(roles),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "control client error: %v\n", err)
		os.Exit(1)
	}
	return client
}

func parseRoles(raw string) []auth.Role {
	parts := strings.Split(raw, ",")
	roles := make([]auth.Role, 0, len(parts))
	for _, part := range parts {
		role := strings.TrimSpace(part)
		if role == "" {
			continue
		}
		roles = append(roles, auth.Role(role))
	}
	return roles
}

func mustConfigVerifier(raw string) *config.ConfigSigner {
	if raw == "" {
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config signing public key error: %v\n", err)
		os.Exit(2)
	}
	verifier, err := config.NewConfigVerifier(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config signing public key error: %v\n", err)
		os.Exit(2)
	}
	return verifier
}
