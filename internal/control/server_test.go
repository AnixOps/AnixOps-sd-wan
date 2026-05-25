package control

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"anixops-sd-wan/internal/auth"
	"anixops-sd-wan/internal/buildinfo"
	"anixops-sd-wan/internal/cert"
	configsign "anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/policy"
	"anixops-sd-wan/internal/store"
	"anixops-sd-wan/internal/telemetry"
)

func TestHealthz(t *testing.T) {
	server := NewServer(buildinfo.Info{Name: "test-control", Version: "test"})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected json content type, got %q", got)
	}
}

func TestVersion(t *testing.T) {
	server := NewServer(buildinfo.Info{Name: "test-control", Version: "test"})
	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestManagementTLSConfigCanRequireClientCertificates(t *testing.T) {
	server := NewServer(buildinfo.Info{Name: "test-control", Version: "test"})

	cfg, err := server.ManagementTLSConfig(true)
	if err != nil {
		t.Fatalf("management tls config: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected TLS 1.2 minimum, got %d", cfg.MinVersion)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("expected client certificate verification, got %v", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatal("expected client CA pool")
	}
}

func TestManagementTLSConfigCanAllowPlainServerTLS(t *testing.T) {
	server := NewServer(buildinfo.Info{Name: "test-control", Version: "test"})

	cfg, err := server.ManagementTLSConfig(false)
	if err != nil {
		t.Fatalf("management tls config: %v", err)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("expected no client cert requirement, got %v", cfg.ClientAuth)
	}
}

func TestConsole(t *testing.T) {
	server := NewServer(buildinfo.Info{Name: "test-control", Version: "test"})
	req := httptest.NewRequest(http.MethodGet, "/console", nil)
	rec := httptest.NewRecorder()

	server.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("expected html content type, got %q", got)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("AnixOps Control")) {
		t.Fatal("expected console body to contain title")
	}
	for _, want := range [][]byte{
		[]byte("data-console-app"),
		[]byte("tenantId"),
		[]byte("actorId"),
		[]byte("roles"),
		[]byte("bearer"),
		[]byte("auditSearchForm"),
		[]byte("createDeviceForm"),
		[]byte("createNodeForm"),
		[]byte("retireNodeForm"),
		[]byte("node-retirements"),
		[]byte("createPolicyForm"),
		[]byte("createConfigForm"),
		[]byte("configWatchForm"),
		[]byte("signed-config-watch"),
		[]byte("issueCertificateForm"),
		[]byte("certificateStatusForm"),
		[]byte("certificateOCSPForm"),
		[]byte("rotateCertificateForm"),
		[]byte("revokeCertificateForm"),
		[]byte("loginForm"),
		[]byte("signingKeyApprovalRequest"),
		[]byte("rotateSigningKey"),
		[]byte("certificate-revocation-list"),
		[]byte("certificate-ocsp"),
		[]byte("oidcLoginForm"),
		[]byte("/v1/oidc-login"),
		[]byte("config-signing-key/approval-request"),
	} {
		if !bytes.Contains(rec.Body.Bytes(), want) {
			t.Fatalf("expected console body to contain %q", string(want))
		}
	}
}

func TestConsoleBrowserAutomation(t *testing.T) {
	chromium, err := exec.LookPath("chromium")
	if err != nil {
		t.Skip("chromium is required for browser automation coverage")
	}

	server := NewServer(buildinfo.Info{Name: "test-control", Version: "test"})
	handler := server.Handler()
	doJSON(t, handler, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"}, http.StatusCreated, nil)
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/devices", domain.Device{
		ID:       "agent-a",
		Kind:     domain.DeviceClient,
		Name:     "Agent A",
		Platform: "linux/amd64",
	}, http.StatusCreated, nil)
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/nodes", domain.Node{
		ID:       "edge-a",
		Role:     domain.NodeOverseasEdge,
		Region:   "hk",
		Endpoint: "edge.example.com:443",
	}, http.StatusCreated, nil)

	base := httptest.NewServer(handler)
	t.Cleanup(base.Close)

	wsURL, cleanup := launchChromiumDebugger(t, chromium, base.URL+"/console")
	t.Cleanup(cleanup)

	runConsoleBrowserScript(t, wsURL, base.URL)
}

func TestTenantDeviceInventoryAPI(t *testing.T) {
	handler := NewServer(buildinfo.Info{Name: "test-control", Version: "test"}).Handler()

	doJSON(t, handler, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"}, http.StatusCreated, nil)
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/devices", domain.Device{
		ID:       "agent-a",
		Kind:     domain.DeviceClient,
		Name:     "Agent A",
		Platform: "linux/amd64",
	}, http.StatusCreated, nil)

	var inventory domain.Inventory
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/inventory", nil, http.StatusOK, &inventory)
	if len(inventory.Devices) != 1 {
		t.Fatalf("expected one device, got %d", len(inventory.Devices))
	}
	if inventory.Devices[0].TenantID != "tenant-a" {
		t.Fatalf("expected device to be scoped to tenant-a, got %q", inventory.Devices[0].TenantID)
	}
	var auditEvents []domain.AuditEvent
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit", nil, http.StatusOK, &auditEvents)
	if !hasAuditActionByActor(auditEvents, "tenant.create", "tenant", "tenant-a", "admin-a") {
		t.Fatalf("expected actor-aware tenant create audit event, got %+v", auditEvents)
	}
	if !hasAuditActionByActor(auditEvents, "device.register", "device", "agent-a", "admin-a") {
		t.Fatalf("expected actor-aware device register audit event, got %+v", auditEvents)
	}
	var deviceEvents []domain.AuditEvent
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit?action=device.register&actor=admin-a&object_type=device&object_id=agent-a", nil, http.StatusOK, &deviceEvents)
	if len(deviceEvents) != 1 || deviceEvents[0].ObjectID != "agent-a" || deviceEvents[0].Actor != "admin-a" {
		t.Fatalf("expected searchable device audit event, got %+v", deviceEvents)
	}
	var noEvents []domain.AuditEvent
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit?action=node.register", nil, http.StatusOK, &noEvents)
	if len(noEvents) != 0 {
		t.Fatalf("expected filtered audit query with no matches, got %+v", noEvents)
	}
	deviceAuditTime := deviceEvents[0].CreatedAt.Format(time.RFC3339Nano)
	var windowEvents []domain.AuditEvent
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit?action=device.register&actor=admin-a&since="+deviceAuditTime+"&until="+deviceAuditTime, nil, http.StatusOK, &windowEvents)
	if len(windowEvents) != 1 || windowEvents[0].ObjectID != "agent-a" {
		t.Fatalf("expected time-windowed device audit event, got %+v", windowEvents)
	}
	var limitedEvents []domain.AuditEvent
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit?limit=1", nil, http.StatusOK, &limitedEvents)
	if len(limitedEvents) != 1 {
		t.Fatalf("expected audit limit to return one event, got %+v", limitedEvents)
	}
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit?since=not-a-time", nil, http.StatusBadRequest, nil)
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit?limit=0", nil, http.StatusBadRequest, nil)
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit?since=2026-01-02T00:00:00Z&until=2026-01-01T00:00:00Z", nil, http.StatusBadRequest, nil)
}

func TestTenantAPIsRequireAuthorization(t *testing.T) {
	handler := NewServer(buildinfo.Info{Name: "test-control", Version: "test"}).Handler()

	req := jsonRequest(t, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized without auth headers, got %d: %s", rec.Code, rec.Body.String())
	}

	doJSON(t, handler, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"}, http.StatusCreated, nil)
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/configs", domain.ConfigBundle{
		ID:       "cfg-agent",
		TargetID: "agent-a",
		Version:  "v1",
	}, http.StatusCreated, nil)

	agentReadReq := jsonRequest(t, http.MethodGet, "/v1/tenants/tenant-a/signed-configs", nil)
	setAuth(agentReadReq, "tenant-a", "agent-a", "agent")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, agentReadReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected agent signed config read, got %d: %s", rec.Code, rec.Body.String())
	}

	agentTelemetryReq := jsonRequest(t, http.MethodPost, "/v1/tenants/tenant-a/telemetry", telemetry.Report{
		SubjectID:   "agent-a",
		SubjectKind: telemetry.SubjectAgent,
	})
	setAuth(agentTelemetryReq, "tenant-a", "agent-a", "agent")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, agentTelemetryReq)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected agent telemetry write, got %d: %s", rec.Code, rec.Body.String())
	}

	agentManageReq := jsonRequest(t, http.MethodPost, "/v1/tenants/tenant-a/devices", domain.Device{
		ID:   "agent-denied",
		Kind: domain.DeviceClient,
		Name: "Denied",
	})
	setAuth(agentManageReq, "tenant-a", "agent-a", "agent")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, agentManageReq)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected agent management denial, got %d: %s", rec.Code, rec.Body.String())
	}

	viewerReq := jsonRequest(t, http.MethodPost, "/v1/tenants/tenant-a/policies", policy.Rule{
		ID:           "ai-openai",
		Priority:     100,
		DomainSuffix: "openai.com",
		Class:        policy.ClassAI,
		EgressNodeID: "jp-egress",
	})
	setAuth(viewerReq, "tenant-a", "viewer-a", "viewer")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, viewerReq)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden for viewer policy write, got %d: %s", rec.Code, rec.Body.String())
	}

	crossTenantReq := jsonRequest(t, http.MethodGet, "/v1/tenants/tenant-a/inventory", nil)
	setAuth(crossTenantReq, "tenant-b", "admin-b", "admin")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, crossTenantReq)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden for cross-tenant read, got %d: %s", rec.Code, rec.Body.String())
	}

	var denied []domain.AuditEvent
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit?action=auth.denied&actor=agent-a&object_type=authorization&object_id=manage", nil, http.StatusOK, &denied)
	if len(denied) != 1 {
		t.Fatalf("expected agent management denial audit event, got %+v", denied)
	}
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit?action=auth.denied&actor=viewer-a&object_type=authorization&object_id=policy.edit", nil, http.StatusOK, &denied)
	if len(denied) != 1 {
		t.Fatalf("expected viewer policy denial audit event, got %+v", denied)
	}
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit?action=auth.denied&actor=admin-b&object_type=authorization&object_id=read", nil, http.StatusOK, &denied)
	if len(denied) != 1 {
		t.Fatalf("expected cross-tenant read denial audit event, got %+v", denied)
	}
}

func TestTenantAPIsAcceptBearerSession(t *testing.T) {
	server := NewServer(buildinfo.Info{Name: "test-control", Version: "test"})
	handler := server.Handler()
	session, err := server.IssueSession(auth.Subject{
		ID:       "admin-a",
		TenantID: "tenant-a",
		Roles:    []auth.Role{auth.RoleAdmin},
	}, time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	req := jsonRequest(t, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"})
	req.Header.Set("Authorization", "Bearer "+session.Token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected bearer session tenant create, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestNodeHeartbeatAPIUpdatesInventoryWithTelemetryWriteRole(t *testing.T) {
	handler := NewServer(buildinfo.Info{Name: "test-control", Version: "test"}).Handler()

	doJSON(t, handler, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"}, http.StatusCreated, nil)
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/nodes", domain.Node{
		ID:       "edge-a",
		Role:     domain.NodeOverseasEdge,
		Region:   "hk",
		Endpoint: "old.example.com:443",
	}, http.StatusCreated, nil)

	req := jsonRequest(t, http.MethodPost, "/v1/tenants/tenant-a/node-heartbeats", domain.NodeHeartbeat{
		NodeID:   "edge-a",
		Healthy:  true,
		Endpoint: "new.example.com:443",
	})
	setAuth(req, "tenant-a", "edge-a", "agent")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected node heartbeat update, got %d: %s", rec.Code, rec.Body.String())
	}

	var inventory domain.Inventory
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/inventory", nil, http.StatusOK, &inventory)
	if len(inventory.Nodes) != 1 || inventory.Nodes[0].ID != "edge-a" || !inventory.Nodes[0].Healthy || inventory.Nodes[0].Endpoint != "new.example.com:443" {
		t.Fatalf("expected heartbeat to update inventory node, got %+v", inventory.Nodes)
	}
	var auditEvents []domain.AuditEvent
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit", nil, http.StatusOK, &auditEvents)
	if !hasAuditActionByActor(auditEvents, "node.register", "node", "edge-a", "admin-a") {
		t.Fatalf("expected actor-aware node register audit event, got %+v", auditEvents)
	}
	if !hasAuditActionByActor(auditEvents, "node.heartbeat", "node", "edge-a", "edge-a") {
		t.Fatalf("expected actor-aware node heartbeat audit event, got %+v", auditEvents)
	}

	var retired domain.Node
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/node-retirements", map[string]string{
		"node_id": "edge-a",
	}, http.StatusOK, &retired)
	if retired.ID != "edge-a" || retired.Healthy {
		t.Fatalf("expected retired node, got %+v", retired)
	}
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/inventory", nil, http.StatusOK, &inventory)
	if len(inventory.Nodes) != 0 {
		t.Fatalf("expected retired node to be removed from inventory, got %+v", inventory.Nodes)
	}
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit?action=node.retire&actor=admin-a&object_type=node&object_id=edge-a", nil, http.StatusOK, &auditEvents)
	if len(auditEvents) != 1 {
		t.Fatalf("expected searchable node retirement audit event, got %+v", auditEvents)
	}
}

func TestSessionAPIsIssueAndRevokeBearerSession(t *testing.T) {
	handler := NewServer(buildinfo.Info{Name: "test-control", Version: "test"}).Handler()

	var session auth.Session
	req := jsonRequest(t, http.MethodPost, "/v1/sessions", sessionIssueRequest{TTLHours: 1})
	setAuth(req, "tenant-a", "admin-a", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected session creation, got %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&session); err != nil {
		t.Fatalf("decode session: %v", err)
	}
	if session.Token == "" || session.Subject.ID != "admin-a" {
		t.Fatalf("unexpected session: %+v", session)
	}

	req = jsonRequest(t, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"})
	req.Header.Set("Authorization", "Bearer "+session.Token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected bearer session tenant create, got %d: %s", rec.Code, rec.Body.String())
	}

	req = jsonRequest(t, http.MethodDelete, "/v1/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected session revoke, got %d: %s", rec.Code, rec.Body.String())
	}

	req = jsonRequest(t, http.MethodGet, "/v1/tenants/tenant-a/inventory", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected revoked bearer denial, got %d: %s", rec.Code, rec.Body.String())
	}
	var auditEvents []domain.AuditEvent
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit", nil, http.StatusOK, &auditEvents)
	for _, want := range []string{"auth.session.issue", "auth.session.revoke"} {
		if !hasAuditAction(auditEvents, want, "admin-a") {
			t.Fatalf("expected session audit event %s, got %+v", want, auditEvents)
		}
	}
}

func TestPasswordLoginIssuesBearerSession(t *testing.T) {
	server := NewServer(buildinfo.Info{Name: "test-control", Version: "test"})
	user, err := auth.NewPasswordUser("tenant-a", "admin-a", "correct-password", []auth.Role{auth.RoleAdmin}, 1000)
	if err != nil {
		t.Fatalf("new password user: %v", err)
	}
	authenticator, err := auth.NewPasswordAuthenticator([]auth.PasswordUser{user})
	if err != nil {
		t.Fatalf("new password authenticator: %v", err)
	}
	server.SetPasswordAuthenticator(authenticator)
	handler := server.Handler()

	var session auth.Session
	req := jsonRequest(t, http.MethodPost, "/v1/login", passwordLoginRequest{
		TenantID:  "tenant-a",
		SubjectID: "admin-a",
		Password:  "correct-password",
		TTLHours:  1,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected password login success, got %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&session); err != nil {
		t.Fatalf("decode session: %v", err)
	}

	createReq := jsonRequest(t, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"})
	createReq.Header.Set("Authorization", "Bearer "+session.Token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, createReq)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected bearer session from password login to authorize tenant create, got %d: %s", rec.Code, rec.Body.String())
	}

	badReq := jsonRequest(t, http.MethodPost, "/v1/login", passwordLoginRequest{
		TenantID:  "tenant-a",
		SubjectID: "admin-a",
		Password:  "wrong-password",
	})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, badReq)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected wrong password denial, got %d: %s", rec.Code, rec.Body.String())
	}
	var auditEvents []domain.AuditEvent
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit", nil, http.StatusOK, &auditEvents)
	if !hasAuditAction(auditEvents, "auth.login", "admin-a") {
		t.Fatalf("expected password login audit event, got %+v", auditEvents)
	}
}

func TestOIDCLoginIssuesBearerSession(t *testing.T) {
	server := NewServer(buildinfo.Info{Name: "test-control", Version: "test"})
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

	doJSON(t, handler, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"}, http.StatusCreated, nil)
	now := time.Now().UTC()
	idToken := oidcIDToken(t, "secret", map[string]interface{}{
		"iss":       "https://idp.example.com",
		"aud":       "anixops-control",
		"sub":       "operator-a",
		"tenant_id": "tenant-a",
		"roles":     []string{"operator"},
		"iat":       now.Unix(),
		"exp":       now.Add(time.Hour).Unix(),
	})

	var session auth.Session
	req := jsonRequest(t, http.MethodPost, "/v1/oidc-login", oidcLoginRequest{
		IDToken:  idToken,
		TTLHours: 1,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected oidc login session, got %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&session); err != nil {
		t.Fatalf("decode oidc session: %v", err)
	}
	if session.Token == "" || session.Subject.ID != "operator-a" || len(session.Subject.Roles) != 1 || session.Subject.Roles[0] != auth.RoleOperator {
		t.Fatalf("unexpected oidc session: %+v", session)
	}

	req = jsonRequest(t, http.MethodGet, "/v1/tenants/tenant-a/inventory", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected oidc bearer read access, got %d: %s", rec.Code, rec.Body.String())
	}

	var auditEvents []domain.AuditEvent
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit?action=auth.login&actor=operator-a&object_type=subject&object_id=operator-a", nil, http.StatusOK, &auditEvents)
	if len(auditEvents) != 1 {
		t.Fatalf("expected oidc login audit event, got %+v", auditEvents)
	}

	req = jsonRequest(t, http.MethodPost, "/v1/oidc-login", oidcLoginRequest{
		IDToken:  oidcIDToken(t, "wrong-secret", map[string]interface{}{"iss": "https://idp.example.com"}),
		TTLHours: 1,
	})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected invalid oidc token denial, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTenantAPIsAcceptAgentPeerCertificate(t *testing.T) {
	handler := NewServer(buildinfo.Info{Name: "test-control", Version: "test"}).Handler()
	doJSON(t, handler, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"}, http.StatusCreated, nil)
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/configs", domain.ConfigBundle{
		ID:       "cfg-agent",
		TargetID: "agent-a",
		Version:  "v1",
	}, http.StatusCreated, nil)
	var issued cert.Issued
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/certificates", certificateIssueRequest{
		DeviceID: "agent-a",
		Role:     "agent",
		TTLHours: 1,
	}, http.StatusCreated, &issued)

	req := jsonRequest(t, http.MethodGet, "/v1/tenants/tenant-a/signed-configs", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{parseCertificate(t, issued.Record.CertPEM)}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected peer certificate config read, got %d: %s", rec.Code, rec.Body.String())
	}

	manageReq := jsonRequest(t, http.MethodPost, "/v1/tenants/tenant-a/devices", domain.Device{
		ID:   "agent-denied",
		Kind: domain.DeviceClient,
		Name: "Denied",
	})
	manageReq.TLS = req.TLS
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, manageReq)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected peer certificate management denial, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTelemetryAPIRedactsSensitiveFields(t *testing.T) {
	handler := NewServer(buildinfo.Info{Name: "test-control", Version: "test"}).Handler()

	doJSON(t, handler, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"}, http.StatusCreated, nil)
	var created telemetry.Report
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/telemetry", telemetry.Report{
		SubjectID:   "agent-a",
		SubjectKind: telemetry.SubjectAgent,
		Logs: []telemetry.LogRecord{{
			Level:   "info",
			Message: "connected",
			Fields:  map[string]string{"token": "secret-token"},
		}},
	}, http.StatusCreated, &created)

	if created.Logs[0].Fields["token"] != "[redacted]" {
		t.Fatalf("expected token redaction, got %q", created.Logs[0].Fields["token"])
	}
}

func TestPolicyAndConfigAPIs(t *testing.T) {
	server := NewServer(buildinfo.Info{Name: "test-control", Version: "test"})
	handler := server.Handler()

	doJSON(t, handler, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"}, http.StatusCreated, nil)
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/policies", policy.Rule{
		ID:           "ai-openai",
		Priority:     100,
		DomainSuffix: "openai.com",
		Class:        policy.ClassAI,
		EgressNodeID: "jp-egress",
	}, http.StatusCreated, nil)

	var decision policy.Decision
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/policy-decisions", policy.Request{
		Domain: "api.openai.com",
		Class:  policy.ClassAI,
	}, http.StatusOK, &decision)
	if decision.EgressNodeID != "jp-egress" {
		t.Fatalf("expected jp-egress decision, got %+v", decision)
	}

	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/configs", domain.ConfigBundle{
		ID:       "cfg-1",
		TargetID: "agent-a",
		Version:  "v1",
		Values:   map[string]string{"transport": "hysteria2"},
	}, http.StatusCreated, nil)
	var configs []domain.ConfigBundle
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/configs", nil, http.StatusOK, &configs)
	if len(configs) != 1 || configs[0].Version != "v1" {
		t.Fatalf("expected v1 config, got %+v", configs)
	}

	var signed []configsign.SignedBundle
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/signed-configs", nil, http.StatusOK, &signed)
	if len(signed) != 1 {
		t.Fatalf("expected one signed config, got %+v", signed)
	}
	verifier, err := configsign.NewConfigVerifier(server.ConfigSigningPublicKey())
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := verifier.Verify(signed[0]); err != nil {
		t.Fatalf("verify signed config: %v", err)
	}
	var auditEvents []domain.AuditEvent
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit", nil, http.StatusOK, &auditEvents)
	if !hasAuditActionByActor(auditEvents, "policy.upsert", "policy_rule", "ai-openai", "admin-a") {
		t.Fatalf("expected actor-aware policy upsert audit event, got %+v", auditEvents)
	}
	if !hasAuditActionByActor(auditEvents, "config.upsert", "config_bundle", "cfg-1", "admin-a") {
		t.Fatalf("expected actor-aware config upsert audit event, got %+v", auditEvents)
	}
}

func TestPolicyDecisionClassifiesObservedTrafficWhenConfigured(t *testing.T) {
	server := NewServer(buildinfo.Info{Name: "test-control", Version: "test"})
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

	doJSON(t, handler, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"}, http.StatusCreated, nil)
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/policies", policy.Rule{
		ID:           "ai-class",
		Priority:     100,
		Class:        policy.ClassAI,
		EgressNodeID: "jp-egress",
	}, http.StatusCreated, nil)

	var decision policy.Decision
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/policy-decisions", policy.Request{
		Domain: "api.openai.com",
	}, http.StatusOK, &decision)
	if decision.Class != policy.ClassAI || decision.EgressNodeID != "jp-egress" || decision.RuleID != "ai-class" {
		t.Fatalf("expected classified ai decision, got %+v", decision)
	}
}

func TestConfigWatchReturnsChangedTargetConfig(t *testing.T) {
	handler := NewServer(buildinfo.Info{Name: "test-control", Version: "test"}).Handler()

	doJSON(t, handler, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"}, http.StatusCreated, nil)
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/configs", domain.ConfigBundle{
		ID:       "cfg-1",
		TargetID: "agent-a",
		Version:  "v1",
		Values:   map[string]string{"transport": "hysteria2"},
	}, http.StatusCreated, nil)

	var bundle domain.ConfigBundle
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/config-watch?target_id=agent-a&since_version=v0&timeout_ms=50", nil, http.StatusOK, &bundle)
	if bundle.TargetID != "agent-a" || bundle.Version != "v1" {
		t.Fatalf("expected watched v1 config, got %+v", bundle)
	}
}

func TestSignedConfigWatchReturnsVerifiableBundle(t *testing.T) {
	server := NewServer(buildinfo.Info{Name: "test-control", Version: "test"})
	handler := server.Handler()

	doJSON(t, handler, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"}, http.StatusCreated, nil)
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/configs", domain.ConfigBundle{
		ID:       "cfg-1",
		TargetID: "agent-a",
		Version:  "v1",
		Values:   map[string]string{"transport": "hysteria2"},
	}, http.StatusCreated, nil)

	var signed configsign.SignedBundle
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/signed-config-watch?target_id=agent-a&since_version=v0&timeout_ms=50", nil, http.StatusOK, &signed)
	if signed.Bundle.TargetID != "agent-a" || signed.Bundle.Version != "v1" {
		t.Fatalf("expected signed watched v1 config, got %+v", signed.Bundle)
	}
	verifier, err := configsign.NewConfigVerifier(server.ConfigSigningPublicKey())
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := verifier.Verify(signed); err != nil {
		t.Fatalf("verify signed watched config: %v", err)
	}
}

func TestConfigWatchWaitsForNewVersion(t *testing.T) {
	handler := NewServer(buildinfo.Info{Name: "test-control", Version: "test"}).Handler()

	doJSON(t, handler, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"}, http.StatusCreated, nil)
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/configs", domain.ConfigBundle{
		ID:       "cfg-1",
		TargetID: "agent-a",
		Version:  "v1",
	}, http.StatusCreated, nil)

	done := make(chan domain.ConfigBundle, 1)
	errCh := make(chan string, 1)
	go func() {
		req := httptest.NewRequest(http.MethodGet, "/v1/tenants/tenant-a/config-watch?target_id=agent-a&since_version=v1&timeout_ms=1000", nil)
		setAuth(req, "tenant-a", "agent-a", "agent")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			errCh <- rec.Body.String()
			return
		}
		var bundle domain.ConfigBundle
		if err := json.NewDecoder(rec.Body).Decode(&bundle); err != nil {
			errCh <- err.Error()
			return
		}
		done <- bundle
	}()

	time.Sleep(100 * time.Millisecond)
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/configs", domain.ConfigBundle{
		ID:       "cfg-2",
		TargetID: "agent-a",
		Version:  "v2",
	}, http.StatusCreated, nil)

	select {
	case bundle := <-done:
		if bundle.Version != "v2" {
			t.Fatalf("expected watched v2 config, got %+v", bundle)
		}
	case err := <-errCh:
		t.Fatalf("config watch failed: %s", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for config watch")
	}
}

func TestConfigSigningKeyCanBeFetchedAndRotated(t *testing.T) {
	server := NewServer(buildinfo.Info{Name: "test-control", Version: "test"})
	handler := server.Handler()

	var key configsign.SigningPublicKey
	doJSON(t, handler, http.MethodGet, "/v1/config-signing-key", nil, http.StatusOK, &key)
	fingerprint, err := key.SHA256Fingerprint()
	if err != nil {
		t.Fatalf("fingerprint fetched key: %v", err)
	}
	if key.SHA256FingerprintHex != fingerprint {
		t.Fatalf("expected fetched key fingerprint %q, got %q", fingerprint, key.SHA256FingerprintHex)
	}
	oldVerifier, err := configsign.NewConfigVerifierFromSigningKey(key)
	if err != nil {
		t.Fatalf("new verifier from signing key: %v", err)
	}

	doJSON(t, handler, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"}, http.StatusCreated, nil)
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/configs", domain.ConfigBundle{
		ID:       "cfg-1",
		TargetID: "agent-a",
		Version:  "v1",
		Values:   map[string]string{"transport": "hysteria2"},
	}, http.StatusCreated, nil)

	var before []configsign.SignedBundle
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/signed-configs", nil, http.StatusOK, &before)
	if err := oldVerifier.Verify(before[0]); err != nil {
		t.Fatalf("old verifier should verify pre-rotation config: %v", err)
	}

	var rotated configsign.SigningPublicKey
	doJSON(t, handler, http.MethodPost, "/v1/config-signing-key", nil, http.StatusOK, &rotated)
	if rotated.PublicKey == key.PublicKey {
		t.Fatal("expected rotated signing key to change public key")
	}
	if rotated.SHA256FingerprintHex == "" || rotated.SHA256FingerprintHex == key.SHA256FingerprintHex {
		t.Fatalf("expected rotated signing key fingerprint to change, got before=%q after=%q", key.SHA256FingerprintHex, rotated.SHA256FingerprintHex)
	}
	newVerifier, err := configsign.NewConfigVerifierFromSigningKey(rotated)
	if err != nil {
		t.Fatalf("new verifier from rotated key: %v", err)
	}
	var after []configsign.SignedBundle
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/signed-configs", nil, http.StatusOK, &after)
	if err := oldVerifier.Verify(after[0]); err == nil {
		t.Fatal("old verifier should reject post-rotation config")
	}
	if err := newVerifier.Verify(after[0]); err != nil {
		t.Fatalf("new verifier should verify post-rotation config: %v", err)
	}
	var events []domain.AuditEvent
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit", nil, http.StatusOK, &events)
	if !hasAuditAction(events, "config_signing_key.rotate", rotated.SHA256FingerprintHex) {
		t.Fatalf("expected signing key rotation audit event, got %+v", events)
	}
}

func TestConfigSigningKeyApprovalRequestRequiresManageRole(t *testing.T) {
	server := NewServer(buildinfo.Info{Name: "test-control", Version: "test"})
	handler := server.Handler()

	doJSON(t, handler, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"}, http.StatusCreated, nil)
	var request configsign.SigningKeyApprovalRequest
	doJSON(t, handler, http.MethodGet, "/v1/config-signing-key/approval-request?source=test&reason=planned", nil, http.StatusOK, &request)
	if request.Kind != configsign.SigningKeyApprovalRequestKind || request.RequestedBy != "admin-a" {
		t.Fatalf("unexpected approval request metadata: %+v", request)
	}
	key, err := request.SigningPublicKey()
	if err != nil {
		t.Fatalf("approval request signing key: %v", err)
	}
	current, err := server.ConfigSigningKey()
	if err != nil {
		t.Fatalf("current signing key: %v", err)
	}
	if key.PublicKey != current.PublicKey || key.SHA256FingerprintHex != current.SHA256FingerprintHex {
		t.Fatalf("approval request key mismatch: %+v want %+v", key, current)
	}
	if request.Source != "test" || request.Reason != "planned" {
		t.Fatalf("expected source/reason from query, got %+v", request)
	}
	var events []domain.AuditEvent
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit", nil, http.StatusOK, &events)
	if !hasAuditAction(events, "config_signing_key.approval_request.export", request.SHA256FingerprintHex) {
		t.Fatalf("expected signing key approval request audit event, got %+v", events)
	}

	viewerReq := jsonRequest(t, http.MethodGet, "/v1/config-signing-key/approval-request", nil)
	setAuth(viewerReq, "tenant-a", "viewer-a", "viewer")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, viewerReq)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected viewer approval request export to be forbidden, got %d: %s", rec.Code, rec.Body.String())
	}
}

func hasAuditAction(events []domain.AuditEvent, action, objectID string) bool {
	for _, event := range events {
		if event.Action == action && event.ObjectID == objectID {
			return true
		}
	}
	return false
}

func hasAuditActionByActor(events []domain.AuditEvent, action, objectType, objectID, actor string) bool {
	for _, event := range events {
		if event.Action == action && event.ObjectType == objectType && event.ObjectID == objectID && event.Actor == actor {
			return true
		}
	}
	return false
}

func TestConfigSigningKeyRotationPersistsWhenConfigured(t *testing.T) {
	var persisted []byte
	server := NewServerWithDependenciesAndSignerPersist(buildinfo.Info{Name: "test-control", Version: "test"}, nil, nil, nil, nil, func(signer *configsign.ConfigSigner) error {
		persisted = signer.PublicKey()
		return nil
	})
	handler := server.Handler()

	var rotated configsign.SigningPublicKey
	doJSON(t, handler, http.MethodPost, "/v1/config-signing-key", nil, http.StatusOK, &rotated)
	rotatedKey, err := rotated.PublicKeyBytes()
	if err != nil {
		t.Fatalf("decode rotated key: %v", err)
	}
	if !bytes.Equal(persisted, rotatedKey) {
		t.Fatal("expected rotation to persist the new signing key before publishing it")
	}
}

func TestCertificateAPIs(t *testing.T) {
	server := NewServer(buildinfo.Info{Name: "test-control", Version: "test"})
	publishDir := t.TempDir()
	publisher, err := cert.NewFileRevocationListPublisher(publishDir)
	if err != nil {
		t.Fatalf("new crl publisher: %v", err)
	}
	server.SetRevocationListPublisher(publisher)
	handler := server.Handler()

	doJSON(t, handler, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"}, http.StatusCreated, nil)

	var issued cert.Issued
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/certificates", certificateIssueRequest{
		DeviceID: "agent-a",
		Role:     "agent",
		TTLHours: 1,
	}, http.StatusCreated, &issued)
	if issued.Record.Serial == "" {
		t.Fatal("expected issued serial")
	}
	if len(issued.PrivateKeyPEM) == 0 {
		t.Fatal("expected private key material in issue response")
	}

	var goodStatus cert.StatusResponse
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/certificate-status?serial="+issued.Record.Serial, nil, http.StatusOK, &goodStatus)
	if goodStatus.State != cert.CertificateGood || goodStatus.Revoked {
		t.Fatalf("expected issued certificate to report good status, got %+v", goodStatus)
	}
	if goodStatus.MaxAgeSeconds <= 0 || goodStatus.NextUpdate.IsZero() {
		t.Fatalf("expected status response cache metadata, got %+v", goodStatus)
	}
	if err := cert.ValidateStatusResponse(goodStatus, cert.StatusRequest{TenantID: "tenant-a", Serial: issued.Record.Serial}, goodStatus.CheckedAt); err != nil {
		t.Fatalf("validate status response: %v", err)
	}

	var unknownStatus cert.StatusResponse
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/certificate-status?serial=missing", nil, http.StatusOK, &unknownStatus)
	if unknownStatus.State != cert.CertificateUnknown {
		t.Fatalf("expected missing certificate to report unknown status, got %+v", unknownStatus)
	}

	var rotated cert.Issued
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/certificate-rotations", certificateRotateRequest{
		Serial:   issued.Record.Serial,
		TTLHours: 2,
	}, http.StatusCreated, &rotated)
	if rotated.Record.Serial == issued.Record.Serial {
		t.Fatal("expected rotated certificate to have a new serial")
	}

	var revokedRecords []cert.Record
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/certificate-revocations", nil, http.StatusOK, &revokedRecords)
	if len(revokedRecords) != 1 || revokedRecords[0].Serial != issued.Record.Serial {
		t.Fatalf("expected old certificate in revocation list, got %+v", revokedRecords)
	}

	var revoked cert.Record
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/certificate-revocations", certificateRevokeRequest{
		Serial: rotated.Record.Serial,
	}, http.StatusOK, &revoked)
	if !revoked.Revoked {
		t.Fatal("expected revoked certificate")
	}

	var revokedStatus cert.StatusResponse
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/certificate-status?serial="+rotated.Record.Serial, nil, http.StatusOK, &revokedStatus)
	if revokedStatus.State != cert.CertificateRevoked || !revokedStatus.Revoked {
		t.Fatalf("expected revoked certificate to report revoked status, got %+v", revokedStatus)
	}
	var auditEvents []domain.AuditEvent
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit", nil, http.StatusOK, &auditEvents)
	for _, want := range []struct {
		action   string
		objectID string
	}{
		{action: "certificate.issue", objectID: issued.Record.Serial},
		{action: "certificate.rotate", objectID: rotated.Record.Serial},
		{action: "certificate.revoke", objectID: revoked.Serial},
	} {
		if !hasAuditAction(auditEvents, want.action, want.objectID) {
			t.Fatalf("expected certificate audit event %s/%s, got %+v", want.action, want.objectID, auditEvents)
		}
	}

	var revocationList cert.RevocationList
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/certificate-revocation-list", nil, http.StatusOK, &revocationList)
	if len(revocationList.Records) != 2 {
		t.Fatalf("expected both revoked certificates in revocation list, got %+v", revocationList.Records)
	}
	block, _ := pem.Decode(revocationList.CRLPEM)
	if block == nil || block.Type != "X509 CRL" {
		t.Fatalf("expected X509 CRL PEM, got block %+v", block)
	}
	parsed, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("parse crl: %v", err)
	}
	serials := make(map[string]bool)
	for _, revokedCertificate := range parsed.RevokedCertificates {
		serials[revokedCertificate.SerialNumber.String()] = true
	}
	if !serials[issued.Record.Serial] || !serials[rotated.Record.Serial] {
		t.Fatalf("expected issued and rotated serials in CRL, got %+v", serials)
	}

	publishedPEM, err := os.ReadFile(filepath.Join(publishDir, "tenant-a.crl.pem"))
	if err != nil {
		t.Fatalf("read published crl pem: %v", err)
	}
	publishedCRL, err := cert.ParseRevocationListPEM(publishedPEM)
	if err != nil {
		t.Fatalf("parse published crl pem: %v", err)
	}
	publishedSerials := make(map[string]bool)
	for _, revokedCertificate := range publishedCRL.RevokedCertificates {
		publishedSerials[revokedCertificate.SerialNumber.String()] = true
	}
	if !publishedSerials[issued.Record.Serial] || !publishedSerials[rotated.Record.Serial] {
		t.Fatalf("expected published CRL to contain issued and rotated serials, got %+v", publishedSerials)
	}
	if _, err := os.Stat(filepath.Join(publishDir, "tenant-a.crl.json")); err != nil {
		t.Fatalf("expected published crl manifest: %v", err)
	}
}

func TestCertificateOCSPAPI(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := cert.NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	server := NewServerWithStoreAndAuthority(buildinfo.Info{Name: "test-control", Version: "test"}, store.NewMemory(), authority)
	handler := server.Handler()

	doJSON(t, handler, http.MethodPost, "/v1/tenants", domain.Tenant{ID: "tenant-a", Name: "Tenant A"}, http.StatusCreated, nil)
	issued, err := authority.Issue(cert.Identity{
		TenantID: "tenant-a",
		DeviceID: "agent-a",
		Role:     "agent",
	}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	caCert := parseCertificate(t, authority.CAPEM())
	issuedCert := parseCertificate(t, issued.Record.CertPEM)
	requestDER, err := cert.NewOCSPRequest(issuedCert, caCert)
	if err != nil {
		t.Fatalf("new ocsp request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/tenants/tenant-a/certificate-ocsp", bytes.NewReader(requestDER))
	req.Header.Set("Content-Type", "application/ocsp-request")
	setAuth(req, "tenant-a", "admin-a", "admin")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected OCSP status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/ocsp-response" {
		t.Fatalf("expected OCSP response content type, got %q", got)
	}
	parsed, err := cert.ParseOCSPResponseDER(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parse ocsp response: %v", err)
	}
	if parsed.Status != cert.OCSPSuccessful || parsed.CertificateStatus != cert.CertificateGood || parsed.Serial != issued.Record.Serial {
		t.Fatalf("expected successful good OCSP response, got %+v", parsed)
	}
	if err := cert.VerifyOCSPResponseSignature(rec.Body.Bytes(), caCert); err != nil {
		t.Fatalf("verify ocsp response signature: %v", err)
	}

	if _, err := authority.Revoke(issued.Record.Serial, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("revoke certificate: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/tenants/tenant-a/certificate-ocsp", bytes.NewReader(requestDER))
	req.Header.Set("Content-Type", "application/ocsp-request")
	setAuth(req, "tenant-a", "admin-a", "admin")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected revoked OCSP status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	parsed, err = cert.ParseOCSPResponseDER(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parse revoked ocsp response: %v", err)
	}
	if parsed.CertificateStatus != cert.CertificateRevoked || parsed.RevokedAt.IsZero() {
		t.Fatalf("expected revoked OCSP status, got %+v", parsed)
	}
}

func doJSON(t *testing.T, handler http.Handler, method, path string, payload interface{}, wantStatus int, out interface{}) {
	t.Helper()

	req := jsonRequest(t, method, path, payload)
	setAuth(req, "tenant-a", "admin-a", "admin")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != wantStatus {
		t.Fatalf("%s %s expected status %d, got %d: %s", method, path, wantStatus, rec.Code, rec.Body.String())
	}
	if out != nil {
		if err := json.NewDecoder(rec.Body).Decode(out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
	}
}

func launchChromiumDebugger(t *testing.T, chromium, url string) (string, func()) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	userDataDir := t.TempDir()
	args := []string{
		"--headless=new",
		"--no-sandbox",
		"--disable-gpu",
		"--disable-dev-shm-usage",
		"--no-first-run",
		"--no-default-browser-check",
		"--remote-debugging-port=0",
		"--user-data-dir=" + userDataDir,
		url,
	}
	cmd := exec.CommandContext(ctx, chromium, args...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		t.Fatalf("chromium stderr pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start chromium: %v", err)
	}

	wsURL := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		re := regexp.MustCompile(`DevTools listening on (ws://\S+)`)
		for scanner.Scan() {
			line := scanner.Text()
			if match := re.FindStringSubmatch(line); len(match) == 2 {
				wsURL <- match[1]
				return
			}
		}
		if err := scanner.Err(); err != nil {
			errCh <- err
			return
		}
		errCh <- fmt.Errorf("chromium exited before emitting devtools endpoint")
	}()

	var debuggerURL string
	select {
	case debuggerURL = <-wsURL:
	case err := <-errCh:
		cancel()
		_ = cmd.Wait()
		t.Fatalf("chromium debugger: %v", err)
	case <-ctx.Done():
		cancel()
		_ = cmd.Wait()
		t.Fatal("timed out waiting for chromium devtools endpoint")
	}

	cleanup := func() {
		cancel()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}
	return debuggerURL, cleanup
}

func runConsoleBrowserScript(t *testing.T, wsURL, baseURL string) {
	t.Helper()

	script := `
const wsUrl = process.env.DEVTOOLS_URL;
const baseUrl = process.env.BASE_URL;
const browserUrl = new URL(wsUrl);
const targetResponse = await fetch('http://127.0.0.1:' + browserUrl.port + '/json/list');
const targets = await targetResponse.json();
const pageTarget = targets.find((target) => target.type === 'page' && target.url && target.url.includes('/console'))
  || targets.find((target) => target.type === 'page')
  || targets[0];
if (!pageTarget || !pageTarget.webSocketDebuggerUrl) {
  throw new Error('page target websocket not found');
}
const ws = new WebSocket(pageTarget.webSocketDebuggerUrl);
console.log('debug target', pageTarget.url);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
await new Promise((resolve, reject) => {
  ws.onopen = resolve;
  ws.onerror = (event) => reject(new Error("websocket error"));
});
let nextId = 1;
const pending = new Map();
const events = new Map();
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  if (msg.id) {
    const pendingEntry = pending.get(msg.id);
    if (!pendingEntry) return;
    pending.delete(msg.id);
    if (msg.error) {
      pendingEntry.reject(new Error(msg.error.message || JSON.stringify(msg.error)));
      return;
    }
    pendingEntry.resolve(msg.result);
    return;
  }
  const listeners = events.get(msg.method);
  if (listeners) {
    for (const listener of listeners) listener(msg.params);
  }
};
function send(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}
function once(method) {
  return new Promise((resolve) => {
    const listeners = events.get(method) || [];
    listeners.push(resolve);
    events.set(method, listeners);
  });
}
async function evaluate(expression) {
  const result = await send('Runtime.evaluate', {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
  if (result.exceptionDetails) {
    throw new Error('runtime evaluation failed: ' + JSON.stringify(result.exceptionDetails));
  }
  return result.result.value;
}
async function waitFor(expression, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    last = await evaluate(expression);
    if (last) return last;
    await sleep(100);
  }
  throw new Error('timeout waiting for ' + expression + ' last=' + JSON.stringify(last));
}
await send('Page.enable');
await send('Runtime.enable');
const load = once('Page.loadEventFired');
await send('Page.navigate', { url: baseUrl + '/console' });
await load;
if (!(await evaluate("document.querySelector('[data-console-app]') !== null"))) {
  throw new Error('console app root missing');
}
if (!(await evaluate("document.querySelector('h1').textContent.includes('AnixOps Control')"))) {
  throw new Error('console title missing');
}
await evaluate("document.querySelector('[data-get=\"/healthz\"]').click(); true");
await waitFor("document.querySelector('#status').textContent.includes('200 GET /healthz')");
await waitFor("document.querySelector('#output').textContent.includes('ok')");
console.log('after health', await evaluate("document.querySelector('#status').textContent"));
await evaluate("(() => { const form = document.querySelector('#createDeviceForm'); form.querySelector('[name=id]').value = 'agent-browser'; form.querySelector('[name=name]').value = 'Agent Browser'; form.querySelector('[name=kind]').value = 'client'; form.querySelector('[name=platform]').value = 'linux/amd64'; form.querySelector('button').click(); return true; })()");
await sleep(1500);
console.log('after device sleep', await evaluate("document.querySelector('#status').textContent"));
if (!(await evaluate("document.querySelector('#status').textContent.includes('201 POST /v1/tenants/tenant-a/devices')"))) {
  throw new Error('device create status not updated');
}
if (!(await evaluate("document.querySelector('#output').textContent.includes('agent-browser')"))) {
  throw new Error('device create output not updated');
}
await evaluate("(() => { const form = document.querySelector('#auditSearchForm'); form.querySelector('[name=action]').value = 'device.register'; form.querySelector('[name=actor]').value = 'admin-a'; form.querySelector('[name=object_type]').value = 'device'; form.querySelector('[name=object_id]').value = 'agent-browser'; form.querySelector('button').click(); return true; })()");
await sleep(1500);
console.log('after audit sleep', await evaluate("document.querySelector('#status').textContent"));
if (!(await evaluate("document.querySelector('#output').textContent.includes('device.register')"))) {
  throw new Error('audit search output not updated');
}
await evaluate("(() => { document.querySelector('#certificateOCSPForm button').click(); return true; })()");
await sleep(500);
console.log('after ocsp sleep', await evaluate("document.querySelector('#status').textContent"));
if (!(await evaluate("document.querySelector('#output').textContent.includes('OCSP request base64 is required')"))) {
  throw new Error('ocsp validation output not shown');
}
console.log('browser automation passed');
`

	cmd := exec.Command("node", "-e", script)
	cmd.Env = append(os.Environ(), "DEVTOOLS_URL="+wsURL, "BASE_URL="+baseURL)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("browser automation failed: %v\n%s", err, output)
	}
}

func jsonRequest(t *testing.T, method, path string, payload interface{}) *http.Request {
	t.Helper()

	var body *bytes.Reader
	if payload == nil {
		body = bytes.NewReader(nil)
	} else {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		body = bytes.NewReader(encoded)
	}
	req := httptest.NewRequest(method, path, body)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func setAuth(req *http.Request, tenantID, actorID, roles string) {
	req.Header.Set("X-Tenant-ID", tenantID)
	req.Header.Set("X-Actor-ID", actorID)
	req.Header.Set("X-Roles", roles)
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

func parseCertificate(t *testing.T, data []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("expected certificate PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certificate
}
