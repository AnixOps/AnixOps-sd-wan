package controlclient

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"anixops-sd-wan/internal/auth"
	"anixops-sd-wan/internal/buildinfo"
	"anixops-sd-wan/internal/cert"
	configsign "anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/control"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/policy"
	"anixops-sd-wan/internal/store"
	"anixops-sd-wan/internal/telemetry"
)

func TestClientRunsControlPlaneSyncFlow(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := cert.NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	server := control.NewServerWithStoreAndAuthority(buildinfo.Info{Name: "test-control", Version: "test"}, store.NewMemory(), authority)
	handler := server.Handler()

	client, err := NewWithCredentials("http://control.test", handlerClient(handler), adminCredentials())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx := context.Background()
	if err := client.Healthz(ctx); err != nil {
		t.Fatalf("healthz: %v", err)
	}
	version, err := client.Version(ctx)
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if version.Name != "test-control" || version.Version != "test" {
		t.Fatalf("expected test control version, got %+v", version)
	}

	if _, err := client.CreateTenant(ctx, domain.Tenant{ID: "tenant-a", Name: "Tenant A"}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	session, err := client.IssueSession(ctx, 1)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	bearerClient, err := NewWithBearer("http://control.test", handlerClient(handler), session.Token)
	if err != nil {
		t.Fatalf("new bearer client: %v", err)
	}
	if _, err := bearerClient.RegisterDevice(ctx, "tenant-a", domain.Device{
		ID:       "agent-session",
		Kind:     domain.DeviceClient,
		Name:     "Agent Session",
		Platform: "linux/amd64",
	}); err != nil {
		t.Fatalf("register device with bearer session: %v", err)
	}
	if err := bearerClient.RevokeSession(ctx); err != nil {
		t.Fatalf("revoke session: %v", err)
	}
	if _, err := bearerClient.Configs(ctx, "tenant-a"); err == nil {
		t.Fatal("expected revoked bearer session to be denied")
	}
	device, err := client.RegisterDevice(ctx, "tenant-a", domain.Device{
		ID:       "agent-a",
		Kind:     domain.DeviceClient,
		Name:     "Agent A",
		Platform: "linux/amd64",
	})
	if err != nil {
		t.Fatalf("register device: %v", err)
	}
	if device.TenantID != "tenant-a" {
		t.Fatalf("expected tenant-a device, got %+v", device)
	}
	node, err := client.RegisterNode(ctx, "tenant-a", domain.Node{
		ID:       "edge-a",
		Role:     domain.NodeOverseasEdge,
		Region:   "hk",
		Endpoint: "old.example.com:443",
	})
	if err != nil {
		t.Fatalf("register node: %v", err)
	}
	if node.TenantID != "tenant-a" {
		t.Fatalf("expected tenant-a node, got %+v", node)
	}
	healthyNode, err := client.PushNodeHeartbeat(ctx, "tenant-a", domain.NodeHeartbeat{
		NodeID:   "edge-a",
		Healthy:  true,
		Endpoint: "new.example.com:443",
	})
	if err != nil {
		t.Fatalf("push node heartbeat: %v", err)
	}
	if !healthyNode.Healthy || healthyNode.Endpoint != "new.example.com:443" {
		t.Fatalf("expected healthy node heartbeat result, got %+v", healthyNode)
	}
	inventory, err := client.Inventory(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if len(inventory.Devices) != 2 || len(inventory.Nodes) != 1 || inventory.Nodes[0].Endpoint != "new.example.com:443" {
		t.Fatalf("expected inventory with two devices and updated node, got %+v", inventory)
	}
	retiredNode, err := client.RetireNode(ctx, "tenant-a", "edge-a")
	if err != nil {
		t.Fatalf("retire node: %v", err)
	}
	if retiredNode.ID != "edge-a" || retiredNode.Healthy {
		t.Fatalf("expected retired node result, got %+v", retiredNode)
	}
	retiredInventory, err := client.Inventory(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("inventory after retire: %v", err)
	}
	if len(retiredInventory.Nodes) != 0 {
		t.Fatalf("expected retired node removed from inventory, got %+v", retiredInventory.Nodes)
	}
	nodeAudit, err := client.AuditEvents(ctx, "tenant-a", AuditQuery{
		Action:     "node.retire",
		Actor:      "admin-a",
		ObjectType: "node",
		ObjectID:   "edge-a",
	})
	if err != nil {
		t.Fatalf("audit events: %v", err)
	}
	if len(nodeAudit) != 1 || nodeAudit[0].Action != "node.retire" || nodeAudit[0].ObjectID != "edge-a" {
		t.Fatalf("expected filtered node retirement audit event, got %+v", nodeAudit)
	}
	windowedAudit, err := client.AuditEvents(ctx, "tenant-a", AuditQuery{
		Action: "node.retire",
		Since:  nodeAudit[0].CreatedAt,
		Until:  nodeAudit[0].CreatedAt,
		Limit:  1,
	})
	if err != nil {
		t.Fatalf("time-windowed audit events: %v", err)
	}
	if len(windowedAudit) != 1 || windowedAudit[0].ObjectID != "edge-a" {
		t.Fatalf("expected time-windowed audit event, got %+v", windowedAudit)
	}

	issued, err := client.IssueCertificate(ctx, "tenant-a", "agent-a", "agent", 24)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	if issued.Record.Serial == "" {
		t.Fatal("expected certificate serial")
	}
	status, err := client.CertificateStatus(ctx, "tenant-a", issued.Record.Serial)
	if err != nil {
		t.Fatalf("certificate status: %v", err)
	}
	if status.State != cert.CertificateGood || status.Revoked {
		t.Fatalf("expected issued certificate to report good status, got %+v", status)
	}
	certificateRecords, err := client.Certificates(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("certificates: %v", err)
	}
	if len(certificateRecords) != 1 || certificateRecords[0].Serial != issued.Record.Serial {
		t.Fatalf("expected issued certificate record, got %+v", certificateRecords)
	}
	unknownStatus, err := client.CertificateStatus(ctx, "tenant-a", "missing")
	if err != nil {
		t.Fatalf("unknown certificate status: %v", err)
	}
	if unknownStatus.State != cert.CertificateUnknown {
		t.Fatalf("expected missing certificate to report unknown status, got %+v", unknownStatus)
	}
	caCert := parseClientCertificate(t, authority.CAPEM())
	issuedCert := parseClientCertificate(t, issued.Record.CertPEM)
	requestDER, err := cert.NewOCSPRequest(issuedCert, caCert)
	if err != nil {
		t.Fatalf("new ocsp request: %v", err)
	}
	ocspResponseDER, err := client.CertificateOCSP(ctx, "tenant-a", requestDER)
	if err != nil {
		t.Fatalf("certificate ocsp: %v", err)
	}
	ocspResponse, err := cert.ParseOCSPResponseDER(ocspResponseDER)
	if err != nil {
		t.Fatalf("parse ocsp response: %v", err)
	}
	if ocspResponse.Status != cert.OCSPSuccessful || ocspResponse.CertificateStatus != cert.CertificateGood || ocspResponse.Serial != issued.Record.Serial {
		t.Fatalf("expected successful OCSP response, got %+v", ocspResponse)
	}
	if err := cert.VerifyOCSPResponseSignature(ocspResponseDER, caCert); err != nil {
		t.Fatalf("verify ocsp response signature: %v", err)
	}
	rotated, err := client.RotateCertificate(ctx, "tenant-a", issued.Record.Serial, 24)
	if err != nil {
		t.Fatalf("rotate certificate: %v", err)
	}
	if rotated.Record.Serial == issued.Record.Serial {
		t.Fatal("expected rotated certificate serial")
	}
	revokedStatus, err := client.CertificateStatus(ctx, "tenant-a", issued.Record.Serial)
	if err != nil {
		t.Fatalf("revoked certificate status: %v", err)
	}
	if revokedStatus.State != cert.CertificateRevoked || !revokedStatus.Revoked {
		t.Fatalf("expected rotated-away certificate to report revoked status, got %+v", revokedStatus)
	}
	revokedRotated, err := client.RevokeCertificate(ctx, "tenant-a", rotated.Record.Serial)
	if err != nil {
		t.Fatalf("revoke rotated certificate: %v", err)
	}
	if !revokedRotated.Revoked || revokedRotated.Serial != rotated.Record.Serial {
		t.Fatalf("expected rotated certificate revoke result, got %+v", revokedRotated)
	}
	revoked, err := client.RevokedCertificates(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("revoked certificates: %v", err)
	}
	revokedSerials := map[string]bool{}
	for _, record := range revoked {
		revokedSerials[record.Serial] = true
	}
	if len(revoked) != 2 || !revokedSerials[issued.Record.Serial] || !revokedSerials[rotated.Record.Serial] {
		t.Fatalf("expected old and rotated certificates revoked, got %+v", revoked)
	}
	revocationList, err := client.CertificateRevocationList(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("certificate revocation list: %v", err)
	}
	if len(revocationList.Records) != 2 || len(revocationList.CRLPEM) == 0 {
		t.Fatalf("expected CRL with both certificates revoked, got %+v", revocationList)
	}

	if _, err := client.UpsertConfig(ctx, "tenant-a", domain.ConfigBundle{
		ID:       "cfg-1",
		TargetID: "agent-a",
		Version:  "v1",
		Values:   map[string]string{"transport": "hysteria2"},
	}); err != nil {
		t.Fatalf("upsert config: %v", err)
	}
	configs, err := client.Configs(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("configs: %v", err)
	}
	if len(configs) != 1 || configs[0].Version != "v1" {
		t.Fatalf("expected v1 config, got %+v", configs)
	}
	watched, changed, err := client.WatchConfig(ctx, "tenant-a", "agent-a", "v0", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("watch config: %v", err)
	}
	if !changed || watched.Version != "v1" {
		t.Fatalf("expected watched v1 config, changed=%v bundle=%+v", changed, watched)
	}
	signed, err := client.SignedConfigs(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("signed configs: %v", err)
	}
	if len(signed) != 1 {
		t.Fatalf("expected one signed config, got %+v", signed)
	}
	watchedSigned, changed, err := client.WatchSignedConfig(ctx, "tenant-a", "agent-a", "v0", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("watch signed config: %v", err)
	}
	if !changed || watchedSigned.Bundle.Version != "v1" {
		t.Fatalf("expected watched signed v1 config, changed=%v bundle=%+v", changed, watchedSigned.Bundle)
	}
	signingKey, err := client.ConfigSigningKey(ctx)
	if err != nil {
		t.Fatalf("config signing key: %v", err)
	}
	fingerprint, err := signingKey.SHA256Fingerprint()
	if err != nil {
		t.Fatalf("fingerprint signing key: %v", err)
	}
	if signingKey.SHA256FingerprintHex != fingerprint {
		t.Fatalf("expected signing key fingerprint %q, got %q", fingerprint, signingKey.SHA256FingerprintHex)
	}
	verifier, err := configsign.NewConfigVerifierFromSigningKey(signingKey)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := verifier.Verify(signed[0]); err != nil {
		t.Fatalf("verify signed config: %v", err)
	}
	approvalRequest, err := client.ConfigSigningKeyApprovalRequest(ctx)
	if err != nil {
		t.Fatalf("config signing key approval request: %v", err)
	}
	approvalKey, err := approvalRequest.SigningPublicKey()
	if err != nil {
		t.Fatalf("approval request signing key: %v", err)
	}
	if approvalKey.PublicKey != signingKey.PublicKey || approvalKey.SHA256FingerprintHex != signingKey.SHA256FingerprintHex {
		t.Fatalf("expected approval request to carry current signing key, got %+v want %+v", approvalKey, signingKey)
	}
	rotatedKey, err := client.RotateConfigSigningKey(ctx)
	if err != nil {
		t.Fatalf("rotate config signing key: %v", err)
	}
	if rotatedKey.PublicKey == signingKey.PublicKey {
		t.Fatal("expected rotated signing key to change public key")
	}
	rotatedVerifier, err := configsign.NewConfigVerifierFromSigningKey(rotatedKey)
	if err != nil {
		t.Fatalf("new rotated verifier: %v", err)
	}
	rotatedSigned, err := client.SignedConfigs(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("signed configs after rotation: %v", err)
	}
	if err := verifier.Verify(rotatedSigned[0]); err == nil {
		t.Fatal("old verifier should reject config signed after rotation")
	}
	if err := rotatedVerifier.Verify(rotatedSigned[0]); err != nil {
		t.Fatalf("rotated verifier should verify signed config: %v", err)
	}

	report, err := client.PushTelemetry(ctx, "tenant-a", telemetry.Report{
		SubjectID:   "agent-a",
		SubjectKind: telemetry.SubjectAgent,
		Metrics:     map[string]float64{"rtt_ms": 20},
	})
	if err != nil {
		t.Fatalf("push telemetry: %v", err)
	}
	if report.TenantID != "tenant-a" {
		t.Fatalf("expected tenant scoped telemetry, got %+v", report)
	}
	reports, err := client.Telemetry(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("telemetry: %v", err)
	}
	if len(reports) != 1 || reports[0].Metrics["rtt_ms"] != 20 {
		t.Fatalf("expected pushed telemetry report, got %+v", reports)
	}
}

func TestClientPolicyDecision(t *testing.T) {
	server := control.NewServer(buildinfo.Info{Name: "test-control", Version: "test"})
	classifier, err := policy.NewClassifier([]policy.ClassificationRule{{
		ID:           "ai-domain",
		Priority:     100,
		DomainSuffix: "openai.com",
		Class:        policy.ClassAI,
	}})
	if err != nil {
		t.Fatalf("new classifier: %v", err)
	}
	server.SetTrafficClassifier(classifier)
	handler := server.Handler()

	client, err := NewWithCredentials("http://control.test", handlerClient(handler), adminCredentials())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx := context.Background()
	if _, err := client.CreateTenant(ctx, domain.Tenant{ID: "tenant-a", Name: "Tenant A"}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	if _, err := client.UpsertPolicyRule(ctx, "tenant-a", policy.Rule{
		ID:           "ai-class",
		Priority:     100,
		Class:        policy.ClassAI,
		EgressNodeID: "jp-egress",
	}); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	rules, err := client.PolicyRules(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("policy rules: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "ai-class" {
		t.Fatalf("expected seeded policy rule, got %+v", rules)
	}

	decision, err := client.PolicyDecision(ctx, "tenant-a", policy.Request{Domain: "api.openai.com"})
	if err != nil {
		t.Fatalf("policy decision: %v", err)
	}
	if decision.Class != policy.ClassAI || decision.EgressNodeID != "jp-egress" {
		t.Fatalf("expected jp-egress, got %+v", decision)
	}
}

func TestClientPasswordLogin(t *testing.T) {
	server := control.NewServer(buildinfo.Info{Name: "test-control", Version: "test"})
	user, err := auth.NewPasswordUser("tenant-a", "admin-a", "password", []auth.Role{auth.RoleAdmin}, 1000)
	if err != nil {
		t.Fatalf("new password user: %v", err)
	}
	authenticator, err := auth.NewPasswordAuthenticator([]auth.PasswordUser{user})
	if err != nil {
		t.Fatalf("new password authenticator: %v", err)
	}
	server.SetPasswordAuthenticator(authenticator)
	handler := server.Handler()

	client, err := New("http://control.test", handlerClient(handler))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	session, err := client.Login(context.Background(), "tenant-a", "admin-a", "password", 1)
	if err != nil {
		t.Fatalf("password login: %v", err)
	}
	if session.Token == "" || session.Subject.ID != "admin-a" {
		t.Fatalf("unexpected session: %+v", session)
	}
}

func TestClientOIDCLogin(t *testing.T) {
	server := control.NewServer(buildinfo.Info{Name: "test-control", Version: "test"})
	oidc, err := auth.NewOIDCAuthenticator(auth.OIDCConfig{
		Issuer:     "https://idp.example.com",
		Audience:   "anixops-control",
		HMACSecret: "secret",
	})
	if err != nil {
		t.Fatalf("new oidc authenticator: %v", err)
	}
	server.SetOIDCAuthenticator(oidc)
	handler := server.Handler()

	client, err := New("http://control.test", handlerClient(handler))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	now := time.Now().UTC()
	token := oidcIDToken(t, "secret", map[string]interface{}{
		"iss":       "https://idp.example.com",
		"aud":       "anixops-control",
		"sub":       "operator-a",
		"tenant_id": "tenant-a",
		"roles":     []string{"operator"},
		"exp":       now.Add(time.Hour).Unix(),
	})
	session, err := client.OIDCLogin(context.Background(), token, 1)
	if err != nil {
		t.Fatalf("oidc login: %v", err)
	}
	if session.Token == "" || session.Subject.ID != "operator-a" || session.Subject.Roles[0] != auth.RoleOperator {
		t.Fatalf("unexpected oidc session: %+v", session)
	}
}

func parseClientCertificate(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("expected certificate PEM, got block %+v", block)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certificate
}

func adminCredentials() Credentials {
	return Credentials{
		TenantID: "tenant-a",
		ActorID:  "admin-a",
		Roles:    []auth.Role{auth.RoleAdmin},
	}
}

func handlerClient(handler http.Handler) *http.Client {
	return &http.Client{Transport: handlerTransport{handler: handler}}
}

type handlerTransport struct {
	handler http.Handler
}

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}

func oidcIDToken(t *testing.T, secret string, claims map[string]interface{}) string {
	t.Helper()
	header := encodeJWTPart(t, map[string]string{"alg": "HS256", "typ": "JWT"})
	payload := encodeJWTPart(t, claims)
	signingInput := header + "." + payload
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + signature
}

func encodeJWTPart(t *testing.T, value interface{}) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal jwt part: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}
