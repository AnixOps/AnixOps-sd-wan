package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/telemetry"
	"anixops-sd-wan/internal/transport"
)

func TestLocalHandlerServesSnapshot(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/snapshot", nil)
	rec := httptest.NewRecorder()

	svc.LocalHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var snapshot Snapshot
	if err := json.NewDecoder(rec.Body).Decode(&snapshot); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if snapshot.TenantID != "default" || snapshot.DeviceID != "local-dev" {
		t.Fatalf("unexpected snapshot identity: %+v", snapshot)
	}
	if snapshot.LinkClass != transport.LinkUnknown || !snapshot.UDPAvailable {
		t.Fatalf("expected default link metrics in snapshot: %+v", snapshot)
	}
}

func TestLocalHandlerServesTelemetry(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/telemetry", nil)
	rec := httptest.NewRecorder()

	svc.LocalHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var report telemetry.Report
	if err := json.NewDecoder(rec.Body).Decode(&report); err != nil {
		t.Fatalf("decode telemetry: %v", err)
	}
	if report.TenantID != "default" || report.SubjectID != "local-dev" {
		t.Fatalf("unexpected telemetry identity: %+v", report)
	}
}

func TestLocalHandlerServesConfig(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/config", nil)
	rec := httptest.NewRecorder()

	svc.LocalHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var bundle domain.ConfigBundle
	if err := json.NewDecoder(rec.Body).Decode(&bundle); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if bundle.TenantID != "default" || bundle.TargetID != "local-dev" || bundle.Version != "dev" {
		t.Fatalf("unexpected config bundle: %+v", bundle)
	}
	if bundle.Values["transport"] == "" {
		t.Fatalf("expected transport value, got %+v", bundle.Values)
	}
}

func TestLocalHandlerRejectsWrongMethod(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/snapshot", nil)
	rec := httptest.NewRecorder()

	svc.LocalHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", rec.Code)
	}
}

func TestLocalHandlerAppliesConfig(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/config", mustJSON(t, domain.ConfigBundle{
		ID:       "cfg-local",
		TenantID: "default",
		TargetID: "local-dev",
		Version:  "v2",
		Values:   map[string]string{"transport": "reality"},
	}))
	rec := httptest.NewRecorder()

	svc.LocalHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var snapshot Snapshot
	if err := json.NewDecoder(rec.Body).Decode(&snapshot); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if snapshot.ConfigVersion != "v2" {
		t.Fatalf("expected applied config version, got %+v", snapshot)
	}
	if snapshot.Protocol != transport.ProtocolReality {
		t.Fatalf("expected applied transport protocol, got %+v", snapshot)
	}
}

func TestLocalHandlerRejectsInvalidConfig(t *testing.T) {
	svc, err := NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/config", mustJSON(t, domain.ConfigBundle{
		ID:       "cfg-local",
		TenantID: "wrong",
		TargetID: "local-dev",
		Version:  "v2",
	}))
	rec := httptest.NewRecorder()

	svc.LocalHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func mustJSON(t *testing.T, value interface{}) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(value); err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	return &buf
}
