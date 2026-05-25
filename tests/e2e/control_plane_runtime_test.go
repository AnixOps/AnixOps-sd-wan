package e2e

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anixops-sd-wan/internal/auth"
	"anixops-sd-wan/internal/cert"
	configsign "anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/controlclient"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/policy"
	"anixops-sd-wan/internal/transport"
)

func TestControlPlaneRuntime(t *testing.T) {
	if os.Getenv("ANIXOPS_REQUIRE_CONTROL_PLANE_RUNTIME") != "1" {
		t.Skip("control plane runtime verification is only required in the remote runtime gate")
	}

	controlBin := buildBinary(t, "./cmd/anix-control")
	agentBin := buildBinary(t, "./cmd/anix-agent")
	nodeBin := buildBinary(t, "./cmd/anix-node")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	workDir := t.TempDir()
	controlAddr := fmt.Sprintf("127.0.0.1:%d", freeTCPPort(t))
	storeFile := filepath.Join(workDir, "store.json")
	sessionFile := filepath.Join(workDir, "sessions.json")
	signingKeyFile := filepath.Join(workDir, "config-signing-key.pem")
	signer, err := configsign.NewConfigSigner()
	if err != nil {
		t.Fatalf("create config signer: %v", err)
	}
	signerPEM, err := signer.PrivateKeyPEM()
	if err != nil {
		t.Fatalf("marshal config signer: %v", err)
	}
	if err := os.WriteFile(signingKeyFile, signerPEM, 0o600); err != nil {
		t.Fatalf("write config signing key: %v", err)
	}

	controlCmd := startBinary(t, ctx, controlBin,
		"--addr", controlAddr,
		"--store-file", storeFile,
		"--session-file", sessionFile,
		"--config-signing-key-file", signingKeyFile,
	)
	t.Cleanup(func() { _ = controlCmd })

	baseURL := "http://" + controlAddr
	tenant := domain.Tenant{ID: "tenant-runtime", Name: "Tenant Runtime"}
	client := mustRuntimeClient(t, baseURL, tenant.ID)
	waitForHealthz(t, client)
	signingKey, err := client.ConfigSigningKey(ctx)
	if err != nil {
		t.Fatalf("fetch config signing key: %v", err)
	}
	if _, err := client.CreateTenant(ctx, tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := client.RegisterDevice(ctx, tenant.ID, domain.Device{
		ID:       "agent-runtime",
		TenantID: tenant.ID,
		Kind:     domain.DeviceClient,
		Name:     "Agent Runtime",
		Platform: "linux/amd64",
	}); err != nil {
		t.Fatalf("register device: %v", err)
	}
	if _, err := client.RegisterNode(ctx, tenant.ID, domain.Node{
		ID:       "egress-runtime",
		TenantID: tenant.ID,
		Role:     domain.NodeEgress,
		Region:   "jp",
		Endpoint: "203.0.113.10:51820",
		Healthy:  true,
	}); err != nil {
		t.Fatalf("register node: %v", err)
	}

	bundle := domain.ConfigBundle{
		ID:       "bundle-runtime",
		TenantID: tenant.ID,
		TargetID: "agent-runtime",
		Version:  "v-runtime-1",
		Values: map[string]string{
			"transport": "hysteria2",
		},
		CreatedAt: time.Now().UTC(),
	}
	if _, err := client.UpsertConfig(ctx, tenant.ID, bundle); err != nil {
		t.Fatalf("upsert config: %v", err)
	}

	telemetryQueue := filepath.Join(workDir, "telemetry-queue.json")
	agentCache := filepath.Join(workDir, "agent-cache.json")
	agentOut := runBinary(t, ctx, agentBin,
		"--sync-once",
		"--control-url", baseURL,
		"--tenant-id", tenant.ID,
		"--device-id", "agent-runtime",
		"--config-signing-public-key", signingKey.PublicKey,
		"--cache-file", agentCache,
		"--telemetry-queue-file", telemetryQueue,
	)
	var agentSnapshot map[string]interface{}
	if err := json.Unmarshal([]byte(agentOut.Stdout), &agentSnapshot); err != nil {
		t.Fatalf("decode agent snapshot: %v\nstdout:\n%s\nstderr:\n%s", err, agentOut.Stdout, agentOut.Stderr)
	}
	if agentSnapshot["config_version"] != bundle.Version {
		t.Fatalf("expected agent config version %q, got %+v", bundle.Version, agentSnapshot)
	}
	if agentSnapshot["protocol"] != string(transport.ProtocolHysteria2) {
		t.Fatalf("expected agent protocol hysterias2 from config bundle, got %+v", agentSnapshot)
	}

	reports, err := client.Telemetry(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("load telemetry: %v", err)
	}
	if len(reports) == 0 {
		t.Fatal("expected telemetry report to be pushed by agent sync-once")
	}
	if got := reports[len(reports)-1].Logs[0].Fields["config_version"]; got != bundle.Version {
		t.Fatalf("expected telemetry to include config version %q, got %+v", bundle.Version, reports[len(reports)-1])
	}

	nodeOut := runBinary(t, ctx, nodeBin,
		"--sync-once",
		"--control-url", baseURL,
		"--tenant-id", tenant.ID,
		"--node-id", "egress-runtime",
		"--role", string(domain.NodeEgress),
		"--region", "jp",
		"--endpoint", "203.0.113.10:51820",
		"--healthy=true",
	)
	var nodeSnapshot map[string]interface{}
	if err := json.Unmarshal([]byte(nodeOut.Stdout), &nodeSnapshot); err != nil {
		t.Fatalf("decode node snapshot: %v\nstdout:\n%s\nstderr:\n%s", err, nodeOut.Stdout, nodeOut.Stderr)
	}
	if nodeSnapshot["node_id"] != "egress-runtime" {
		t.Fatalf("expected node snapshot for egress-runtime, got %+v", nodeSnapshot)
	}

	inventory, err := client.Inventory(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("load inventory: %v", err)
	}
	if len(inventory.Nodes) != 1 || inventory.Nodes[0].ID != "egress-runtime" {
		t.Fatalf("expected node heartbeat to update inventory, got %+v", inventory.Nodes)
	}

	if _, err := client.PolicyDecision(ctx, tenant.ID, policy.Request{
		Domain: "api.openai.com",
		Class:  policy.ClassAI,
	}); err != nil {
		t.Fatalf("policy decision call: %v", err)
	}

	cacheOut := runBinary(t, ctx, agentBin,
		"--once",
		"--tenant-id", tenant.ID,
		"--device-id", "agent-runtime",
		"--config-version", "bootstrap",
		"--cache-file", agentCache,
	)
	var cacheSnapshot map[string]interface{}
	if err := json.Unmarshal([]byte(cacheOut.Stdout), &cacheSnapshot); err != nil {
		t.Fatalf("decode cached agent snapshot: %v\nstdout:\n%s\nstderr:\n%s", err, cacheOut.Stdout, cacheOut.Stderr)
	}
	if cacheSnapshot["config_version"] != bundle.Version {
		t.Fatalf("expected cached config version %q after restart, got %+v", bundle.Version, cacheSnapshot)
	}
}

func TestCertificateLifecycleRuntime(t *testing.T) {
	if os.Getenv("ANIXOPS_REQUIRE_CONTROL_PLANE_RUNTIME") != "1" {
		t.Skip("certificate lifecycle runtime verification is only required in the remote runtime gate")
	}

	controlBin := buildBinary(t, "./cmd/anix-control")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	workDir := t.TempDir()
	controlAddr := fmt.Sprintf("127.0.0.1:%d", freeTCPPort(t))
	storeFile := filepath.Join(workDir, "store.json")
	sessionFile := filepath.Join(workDir, "sessions.json")
	crlDir := filepath.Join(workDir, "crl")

	authority, err := cert.NewAuthority("runtime-ca", time.Now().UTC())
	if err != nil {
		t.Fatalf("create authority: %v", err)
	}
	bundle, err := authority.ExportCA()
	if err != nil {
		t.Fatalf("export authority: %v", err)
	}
	caCertFile := filepath.Join(workDir, "ca-cert.pem")
	caKeyFile := filepath.Join(workDir, "ca-key.pem")
	if err := os.WriteFile(caCertFile, bundle.CertificatePEM, 0o600); err != nil {
		t.Fatalf("write ca cert: %v", err)
	}
	if err := os.WriteFile(caKeyFile, bundle.PrivateKeyPEM, 0o600); err != nil {
		t.Fatalf("write ca key: %v", err)
	}

	controlCmd := startBinary(t, ctx, controlBin,
		"--addr", controlAddr,
		"--store-file", storeFile,
		"--session-file", sessionFile,
		"--ca-cert", caCertFile,
		"--ca-key", caKeyFile,
		"--crl-publish-dir", crlDir,
	)
	t.Cleanup(func() { _ = controlCmd })

	baseURL := "http://" + controlAddr
	tenant := domain.Tenant{ID: "tenant-cert-runtime", Name: "Tenant Cert Runtime"}
	client := mustRuntimeClient(t, baseURL, tenant.ID)
	waitForHealthz(t, client)
	if _, err := client.CreateTenant(ctx, tenant); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := client.RegisterDevice(ctx, tenant.ID, domain.Device{
		ID:       "agent-cert-runtime",
		TenantID: tenant.ID,
		Kind:     domain.DeviceClient,
		Name:     "Agent Cert Runtime",
		Platform: "linux/amd64",
	}); err != nil {
		t.Fatalf("register device: %v", err)
	}

	issued, err := client.IssueCertificate(ctx, tenant.ID, "agent-cert-runtime", "agent", 24)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	status, err := client.CertificateStatus(ctx, tenant.ID, issued.Record.Serial)
	if err != nil {
		t.Fatalf("certificate status: %v", err)
	}
	if status.State != cert.CertificateGood || status.Revoked {
		t.Fatalf("expected good certificate status, got %+v", status)
	}

	issuedCert, err := parseCertificatePEM(issued.Record.CertPEM)
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	issuerCert, err := parseCertificatePEM(bundle.CertificatePEM)
	if err != nil {
		t.Fatalf("parse issuer certificate: %v", err)
	}
	requestDER, err := cert.NewOCSPRequest(issuedCert, issuerCert)
	if err != nil {
		t.Fatalf("create ocsp request: %v", err)
	}
	responseDER, err := client.CertificateOCSP(ctx, tenant.ID, requestDER)
	if err != nil {
		t.Fatalf("certificate ocsp: %v", err)
	}
	parsedResponse, err := cert.ParseOCSPResponseDER(responseDER)
	if err != nil {
		t.Fatalf("parse ocsp response: %v", err)
	}
	if parsedResponse.CertificateStatus != cert.CertificateGood || parsedResponse.Serial != issued.Record.Serial {
		t.Fatalf("expected good ocsp response, got %+v", parsedResponse)
	}
	if err := cert.VerifyOCSPResponseSignature(responseDER, issuerCert); err != nil {
		t.Fatalf("verify ocsp response signature: %v", err)
	}

	revoked, err := client.RevokeCertificate(ctx, tenant.ID, issued.Record.Serial)
	if err != nil {
		t.Fatalf("revoke certificate: %v", err)
	}
	if !revoked.Revoked {
		t.Fatalf("expected revoked certificate, got %+v", revoked)
	}
	revokedStatus, err := client.CertificateStatus(ctx, tenant.ID, issued.Record.Serial)
	if err != nil {
		t.Fatalf("revoked certificate status: %v", err)
	}
	if revokedStatus.State != cert.CertificateRevoked || !revokedStatus.Revoked {
		t.Fatalf("expected revoked status, got %+v", revokedStatus)
	}

	httpCRLServer := httptest.NewServer(http.FileServer(http.Dir(crlDir)))
	t.Cleanup(httpCRLServer.Close)
	crlPEM, err := os.ReadFile(filepath.Join(crlDir, tenant.ID+".crl.pem"))
	if err != nil {
		t.Fatalf("read published crl pem: %v", err)
	}
	manifestData, err := os.ReadFile(filepath.Join(crlDir, tenant.ID+".crl.json"))
	if err != nil {
		t.Fatalf("read published crl manifest: %v", err)
	}
	var manifest cert.PublishedRevocationList
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("decode crl manifest: %v", err)
	}
	if manifest.RevokedCount != 1 {
		t.Fatalf("expected one revoked certificate in manifest, got %+v", manifest)
	}
	if sum := sha256.Sum256(crlPEM); fmt.Sprintf("%x", sum[:]) != manifest.SHA256 {
		t.Fatalf("expected manifest sha256 to match crl pem")
	}
	if parsedCRL, err := cert.ParseRevocationListPEM(crlPEM); err != nil || parsedCRL == nil {
		t.Fatalf("parse published crl pem: %v", err)
	}
	if resp, err := http.Get(httpCRLServer.URL + "/" + tenant.ID + ".crl.pem"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch crl pem over http: %v status=%d", err, respStatus(resp))
	}
	if resp, err := http.Get(httpCRLServer.URL + "/" + tenant.ID + ".crl.json"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("fetch crl manifest over http: %v status=%d", err, respStatus(resp))
	}
}

func waitForHealthz(t *testing.T, client *controlclient.Client) {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if err := client.Healthz(context.Background()); err == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("timed out waiting for control healthz")
}

func mustRuntimeClient(t *testing.T, baseURL, tenantID string) *controlclient.Client {
	t.Helper()

	client, err := controlclient.NewWithCredentials(baseURL, nil, controlclient.Credentials{
		TenantID: tenantID,
		ActorID:  "runtime-admin",
		Roles:    []auth.Role{auth.RoleAdmin},
	})
	if err != nil {
		t.Fatalf("new runtime client: %v", err)
	}
	return client
}

func buildBinary(t *testing.T, pkg string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, filepath.Base(pkg))
	cmd := exec.Command("go", "build", "-o", path, pkg)
	cmd.Dir = filepath.Join("..", "..")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, output)
	}
	return path
}

func parseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("certificate PEM is required")
	}
	return x509.ParseCertificate(block.Bytes)
}

func respStatus(resp *http.Response) int {
	if resp == nil {
		return 0
	}
	return resp.StatusCode
}

type binaryOutput struct {
	Stdout string
	Stderr string
}

func startBinary(t *testing.T, ctx context.Context, bin string, args ...string) *exec.Cmd {
	t.Helper()

	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v\nstdout:\n%s\nstderr:\n%s", bin, err, stdout.String(), stderr.String())
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("%s stdout:\n%s", bin, stdout.String())
			t.Logf("%s stderr:\n%s", bin, stderr.String())
		}
	})
	return cmd
}

func runBinary(t *testing.T, ctx context.Context, bin string, args ...string) binaryOutput {
	t.Helper()

	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("run %s: %v\nstdout:\n%s\nstderr:\n%s", bin, err, stdout.String(), stderr.String())
	}
	return binaryOutput{Stdout: stdout.String(), Stderr: stderr.String()}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate tcp port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
