package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"anixops-sd-wan/internal/buildinfo"
	"anixops-sd-wan/internal/cert"
	"anixops-sd-wan/internal/control"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/policy"
	"anixops-sd-wan/internal/telemetry"
)

func TestControlPlaneTenantLifecycle(t *testing.T) {
	handler := control.NewServer(buildinfo.Info{Name: "e2e-control", Version: "test"}).Handler()

	doJSON(t, handler, http.MethodPost, "/v1/tenants", domain.Tenant{
		ID:   "tenant-a",
		Name: "Tenant A",
	}, http.StatusCreated, nil)

	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/devices", domain.Device{
		ID:       "agent-a",
		Kind:     domain.DeviceClient,
		Name:     "Agent A",
		Platform: "linux/amd64",
	}, http.StatusCreated, nil)

	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/nodes", domain.Node{
		ID:       "jp-egress",
		Role:     domain.NodeEgress,
		Region:   "jp",
		Endpoint: "203.0.113.10:51820",
		Healthy:  true,
	}, http.StatusCreated, nil)

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
		t.Fatalf("expected jp-egress policy decision, got %+v", decision)
	}

	var issued cert.Issued
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/certificates", map[string]interface{}{
		"device_id": "agent-a",
		"role":      "agent",
		"ttl_hours": 24,
	}, http.StatusCreated, &issued)
	if issued.Record.Serial == "" {
		t.Fatal("expected certificate serial")
	}

	var goodStatus cert.CertificateStatus
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/certificate-status?serial="+issued.Record.Serial, nil, http.StatusOK, &goodStatus)
	if goodStatus.State != cert.CertificateGood || goodStatus.Revoked {
		t.Fatalf("expected issued certificate status to be good, got %+v", goodStatus)
	}

	var revoked cert.Record
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/certificate-revocations", map[string]interface{}{
		"serial": issued.Record.Serial,
	}, http.StatusOK, &revoked)
	if !revoked.Revoked {
		t.Fatalf("expected certificate to be revoked, got %+v", revoked)
	}

	var revokedStatus cert.CertificateStatus
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/certificate-status?serial="+issued.Record.Serial, nil, http.StatusOK, &revokedStatus)
	if revokedStatus.State != cert.CertificateRevoked || !revokedStatus.Revoked {
		t.Fatalf("expected revoked certificate status, got %+v", revokedStatus)
	}

	var revocationList cert.RevocationList
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/certificate-revocation-list", nil, http.StatusOK, &revocationList)
	if len(revocationList.Records) != 1 || len(revocationList.CRLPEM) == 0 {
		t.Fatalf("expected CRL for revoked certificate, got %+v", revocationList)
	}

	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/telemetry", telemetry.Report{
		SubjectID:   "agent-a",
		SubjectKind: telemetry.SubjectAgent,
		Metrics:     map[string]float64{"rtt_ms": 42},
	}, http.StatusCreated, nil)

	var inventory domain.Inventory
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/inventory", nil, http.StatusOK, &inventory)
	if len(inventory.Devices) != 1 || len(inventory.Nodes) != 1 {
		t.Fatalf("expected one device and one node, got %+v", inventory)
	}

	var retired domain.Node
	doJSON(t, handler, http.MethodPost, "/v1/tenants/tenant-a/node-retirements", map[string]string{
		"node_id": "jp-egress",
	}, http.StatusOK, &retired)
	if retired.ID != "jp-egress" || retired.Healthy {
		t.Fatalf("expected retired node, got %+v", retired)
	}

	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/inventory", nil, http.StatusOK, &inventory)
	if len(inventory.Nodes) != 0 {
		t.Fatalf("expected retired node to be removed from inventory, got %+v", inventory.Nodes)
	}

	var audit []domain.AuditEvent
	doJSON(t, handler, http.MethodGet, "/v1/tenants/tenant-a/audit?action=node.retire&actor=admin-a&object_type=node&object_id=jp-egress", nil, http.StatusOK, &audit)
	if len(audit) != 1 {
		t.Fatalf("expected node retirement audit event, got %+v", audit)
	}
}

func doJSON(t *testing.T, handler http.Handler, method, path string, payload interface{}, wantStatus int, out interface{}) {
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
	req.Header.Set("X-Tenant-ID", "tenant-a")
	req.Header.Set("X-Actor-ID", "admin-a")
	req.Header.Set("X-Roles", "admin")
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
