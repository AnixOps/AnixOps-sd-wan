package cert

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStatusResponderReportsStatusEnvelope(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	issued, err := authority.Issue(Identity{
		TenantID: "tenant-a",
		DeviceID: "agent-a",
		Role:     "agent",
	}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	responder, err := NewStatusResponder(authority, 10*time.Minute)
	if err != nil {
		t.Fatalf("new responder: %v", err)
	}

	checkedAt := now.Add(time.Minute)
	response, err := responder.Respond(StatusRequest{
		TenantID: " tenant-a ",
		Serial:   " " + issued.Record.Serial + " ",
	}, checkedAt)
	if err != nil {
		t.Fatalf("respond status: %v", err)
	}
	if response.State != CertificateGood || response.Revoked {
		t.Fatalf("expected good status, got %+v", response)
	}
	if response.MaxAgeSeconds != 600 {
		t.Fatalf("expected max age seconds 600, got %d", response.MaxAgeSeconds)
	}
	if !response.CheckedAt.Equal(checkedAt) || !response.ThisUpdate.Equal(checkedAt) {
		t.Fatalf("expected checked_at and this_update to match %s, got %+v", checkedAt, response)
	}
	if !response.NextUpdate.Equal(checkedAt.Add(10 * time.Minute)) {
		t.Fatalf("unexpected next update: %s", response.NextUpdate)
	}
	if err := ValidateStatusResponse(response, StatusRequest{TenantID: "tenant-a", Serial: issued.Record.Serial}, checkedAt); err != nil {
		t.Fatalf("validate response: %v", err)
	}

	if _, err := authority.Revoke(issued.Record.Serial, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("revoke certificate: %v", err)
	}
	response, err = responder.Respond(StatusRequest{TenantID: "tenant-a", Serial: issued.Record.Serial}, now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("respond revoked status: %v", err)
	}
	if response.State != CertificateRevoked || !response.Revoked || response.RevokedAt.IsZero() {
		t.Fatalf("expected revoked status, got %+v", response)
	}

	response, err = responder.Respond(StatusRequest{TenantID: "tenant-a", Serial: "missing"}, now.Add(4*time.Minute))
	if err != nil {
		t.Fatalf("respond unknown status: %v", err)
	}
	if response.State != CertificateUnknown || response.TenantID != "tenant-a" || response.Serial != "missing" {
		t.Fatalf("expected unknown status for missing serial, got %+v", response)
	}
}

func TestStatusResponderReportsValidityStates(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	future, err := authority.Issue(Identity{
		TenantID: "tenant-a",
		DeviceID: "future-agent",
		Role:     "agent",
	}, time.Hour, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("issue future certificate: %v", err)
	}
	short, err := authority.Issue(Identity{
		TenantID: "tenant-a",
		DeviceID: "short-agent",
		Role:     "agent",
	}, time.Minute, now)
	if err != nil {
		t.Fatalf("issue short certificate: %v", err)
	}
	responder, err := NewStatusResponder(authority, DefaultStatusMaxAge)
	if err != nil {
		t.Fatalf("new responder: %v", err)
	}

	response, err := responder.Respond(StatusRequest{TenantID: "tenant-a", Serial: future.Record.Serial}, now)
	if err != nil {
		t.Fatalf("respond future status: %v", err)
	}
	if response.State != CertificateNotYetValid {
		t.Fatalf("expected not-yet-valid status, got %+v", response)
	}
	response, err = responder.Respond(StatusRequest{TenantID: "tenant-a", Serial: short.Record.Serial}, now.Add(2*time.Minute))
	if err != nil {
		t.Fatalf("respond expired status: %v", err)
	}
	if response.State != CertificateExpired {
		t.Fatalf("expected expired status, got %+v", response)
	}
}

func TestStatusResponderTreatsCrossTenantSerialAsUnknown(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	issued, err := authority.Issue(Identity{
		TenantID: "tenant-a",
		DeviceID: "agent-a",
		Role:     "agent",
	}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	responder, err := NewStatusResponder(authority, DefaultStatusMaxAge)
	if err != nil {
		t.Fatalf("new responder: %v", err)
	}

	response, err := responder.Respond(StatusRequest{TenantID: "tenant-b", Serial: issued.Record.Serial}, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("respond cross-tenant status: %v", err)
	}
	if response.State != CertificateUnknown || !response.NotBefore.IsZero() || !response.NotAfter.IsZero() {
		t.Fatalf("expected cross-tenant serial to be hidden as unknown, got %+v", response)
	}
}

func TestStatusResponderRejectsInvalidInputsAndMaxAge(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	if _, err := NewStatusResponder(nil, time.Minute); err == nil {
		t.Fatal("expected nil authority to be rejected")
	}
	if _, err := NewStatusResponder(authority, 0); err == nil {
		t.Fatal("expected zero max age to be rejected")
	}
	if _, err := NewStatusResponder(authority, 1500*time.Millisecond); err == nil {
		t.Fatal("expected sub-second max age precision to be rejected")
	}

	responder, err := NewStatusResponder(authority, time.Minute)
	if err != nil {
		t.Fatalf("new responder: %v", err)
	}
	if _, err := responder.Respond(StatusRequest{Serial: "serial"}, now); err == nil || !strings.Contains(err.Error(), "tenant id") {
		t.Fatalf("expected missing tenant error, got %v", err)
	}
	if _, err := responder.Respond(StatusRequest{TenantID: "tenant-a"}, now); err == nil || !strings.Contains(err.Error(), "serial") {
		t.Fatalf("expected missing serial error, got %v", err)
	}
}

func TestStatusResponderHTTPHandler(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	issued, err := authority.Issue(Identity{
		TenantID: "tenant-a",
		DeviceID: "agent-a",
		Role:     "agent",
	}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	checkedAt := now.Add(time.Minute)
	responder, err := NewStatusResponder(authority, 5*time.Minute)
	if err != nil {
		t.Fatalf("new responder: %v", err)
	}
	responder.Clock = func() time.Time { return checkedAt }

	req := httptest.NewRequest(http.MethodGet, "/status?tenant_id=tenant-a&serial="+issued.Record.Serial, nil)
	rec := httptest.NewRecorder()
	responder.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "max-age=300" {
		t.Fatalf("expected cache max-age header, got %q", got)
	}
	var response StatusResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.State != CertificateGood || !response.NextUpdate.Equal(checkedAt.Add(5*time.Minute)) {
		t.Fatalf("unexpected handler response: %+v", response)
	}

	body, err := json.Marshal(StatusRequest{TenantID: "tenant-a", Serial: issued.Record.Serial})
	if err != nil {
		t.Fatalf("marshal post body: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/status", bytes.NewReader(body))
	rec = httptest.NewRecorder()
	responder.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected POST status %d, got %d: %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/status?tenant_id=tenant-a", nil)
	rec = httptest.NewRecorder()
	responder.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected missing serial to return 400, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPut, "/status", nil)
	rec = httptest.NewRecorder()
	responder.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, POST" {
		t.Fatalf("expected method not allowed with allow header, got %d %q", rec.Code, rec.Header().Get("Allow"))
	}
}

func TestValidateStatusResponseRejectsTamperingAndStaleResponses(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	issued, err := authority.Issue(Identity{
		TenantID: "tenant-a",
		DeviceID: "agent-a",
		Role:     "agent",
	}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	responder, err := NewStatusResponder(authority, time.Minute)
	if err != nil {
		t.Fatalf("new responder: %v", err)
	}
	request := StatusRequest{TenantID: "tenant-a", Serial: issued.Record.Serial}
	response, err := responder.Respond(request, now.Add(time.Second))
	if err != nil {
		t.Fatalf("respond status: %v", err)
	}
	if err := ValidateStatusResponse(response, request, now.Add(2*time.Second)); err != nil {
		t.Fatalf("validate response: %v", err)
	}

	tampered := response
	tampered.Serial = "other"
	if err := ValidateStatusResponse(tampered, request, now.Add(2*time.Second)); err == nil {
		t.Fatal("expected serial tampering to be rejected")
	}
	stale := response
	if err := ValidateStatusResponse(stale, request, stale.NextUpdate); err == nil {
		t.Fatal("expected stale response to be rejected")
	}
	inconsistent := response
	inconsistent.Revoked = true
	if err := ValidateStatusResponse(inconsistent, request, now.Add(2*time.Second)); err == nil {
		t.Fatal("expected inconsistent revoked flag to be rejected")
	}
}
