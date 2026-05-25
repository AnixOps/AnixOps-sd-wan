package cert

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOCSPResponderReportsGoodRevokedAndUnknown(t *testing.T) {
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
	caCert := parseTestCertificatePEM(t, authority.CAPEM())
	issuedCert := parseTestCertificatePEM(t, issued.Record.CertPEM)
	requestDER, err := NewOCSPRequest(issuedCert, caCert)
	if err != nil {
		t.Fatalf("new ocsp request: %v", err)
	}
	request, err := ParseOCSPRequestDER(requestDER)
	if err != nil {
		t.Fatalf("parse ocsp request: %v", err)
	}
	if request.Serial != issued.Record.Serial {
		t.Fatalf("expected request serial %q, got %q", issued.Record.Serial, request.Serial)
	}
	responder, err := NewStatusResponder(authority, 10*time.Minute)
	if err != nil {
		t.Fatalf("new status responder: %v", err)
	}

	checkedAt := now.Add(time.Minute)
	responseDER, err := responder.RespondOCSPDER("tenant-a", requestDER, checkedAt)
	if err != nil {
		t.Fatalf("respond ocsp good: %v", err)
	}
	assertOCSPResponse(t, responseDER, caCert, OCSPSuccessful, CertificateGood, issued.Record.Serial, checkedAt, checkedAt.Add(10*time.Minute))

	if _, err := authority.Revoke(issued.Record.Serial, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("revoke certificate: %v", err)
	}
	responseDER, err = responder.RespondOCSPDER("tenant-a", requestDER, now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("respond ocsp revoked: %v", err)
	}
	parsed := assertOCSPResponse(t, responseDER, caCert, OCSPSuccessful, CertificateRevoked, issued.Record.Serial, now.Add(3*time.Minute), now.Add(13*time.Minute))
	if parsed.RevokedAt.IsZero() {
		t.Fatalf("expected revoked response to include revocation time: %+v", parsed)
	}

	responseDER, err = responder.RespondOCSPDER("tenant-b", requestDER, now.Add(4*time.Minute))
	if err != nil {
		t.Fatalf("respond ocsp unknown: %v", err)
	}
	assertOCSPResponse(t, responseDER, caCert, OCSPSuccessful, CertificateUnknown, issued.Record.Serial, now.Add(4*time.Minute), now.Add(14*time.Minute))
}

func TestOCSPResponderRejectsMalformedAndWrongIssuerRequests(t *testing.T) {
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
	otherAuthority, err := NewAuthority("other-ca", now)
	if err != nil {
		t.Fatalf("new other authority: %v", err)
	}
	issuedCert := parseTestCertificatePEM(t, issued.Record.CertPEM)
	wrongIssuer := parseTestCertificatePEM(t, otherAuthority.CAPEM())
	wrongRequestDER, err := NewOCSPRequest(issuedCert, wrongIssuer)
	if err != nil {
		t.Fatalf("new wrong issuer ocsp request: %v", err)
	}
	responder, err := NewStatusResponder(authority, time.Minute)
	if err != nil {
		t.Fatalf("new responder: %v", err)
	}

	responseDER, err := responder.RespondOCSPDER("tenant-a", []byte("not-der"), now)
	if err != nil {
		t.Fatalf("malformed request should return an OCSP error response, got %v", err)
	}
	parsed, err := ParseOCSPResponseDER(responseDER)
	if err != nil {
		t.Fatalf("parse malformed OCSP response: %v", err)
	}
	if parsed.Status != OCSPMalformed {
		t.Fatalf("expected malformed response status, got %+v", parsed)
	}

	responseDER, err = responder.RespondOCSPDER("tenant-a", wrongRequestDER, now)
	if err != nil {
		t.Fatalf("wrong issuer request should return an OCSP error response, got %v", err)
	}
	parsed, err = ParseOCSPResponseDER(responseDER)
	if err != nil {
		t.Fatalf("parse unauthorized OCSP response: %v", err)
	}
	if parsed.Status != OCSPUnauthorized {
		t.Fatalf("expected unauthorized response status, got %+v", parsed)
	}
}

func TestStatusResponderServeOCSPHTTP(t *testing.T) {
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
	caCert := parseTestCertificatePEM(t, authority.CAPEM())
	issuedCert := parseTestCertificatePEM(t, issued.Record.CertPEM)
	requestDER, err := NewOCSPRequest(issuedCert, caCert)
	if err != nil {
		t.Fatalf("new ocsp request: %v", err)
	}
	checkedAt := now.Add(time.Minute)
	responder, err := NewStatusResponder(authority, 5*time.Minute)
	if err != nil {
		t.Fatalf("new responder: %v", err)
	}
	responder.Clock = func() time.Time { return checkedAt }

	req := httptest.NewRequest(http.MethodPost, "/ocsp", bytes.NewReader(requestDER))
	req.Header.Set("Content-Type", "application/ocsp-request")
	rec := httptest.NewRecorder()
	responder.ServeOCSPHTTP("tenant-a", rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected OCSP HTTP status 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/ocsp-response" {
		t.Fatalf("expected OCSP response content type, got %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "max-age=300" {
		t.Fatalf("expected cache max-age header, got %q", got)
	}
	assertOCSPResponse(t, rec.Body.Bytes(), caCert, OCSPSuccessful, CertificateGood, issued.Record.Serial, checkedAt, checkedAt.Add(5*time.Minute))

	req = httptest.NewRequest(http.MethodGet, "/ocsp", nil)
	rec = httptest.NewRecorder()
	responder.ServeOCSPHTTP("tenant-a", rec, req)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" {
		t.Fatalf("expected POST-only OCSP endpoint, got %d allow %q", rec.Code, rec.Header().Get("Allow"))
	}
}

func assertOCSPResponse(t *testing.T, responseDER []byte, issuer *x509.Certificate, wantStatus OCSPResponseStatus, wantCertStatus CertificateState, wantSerial string, wantThisUpdate, wantNextUpdate time.Time) ParsedOCSPResponse {
	t.Helper()
	parsed, err := ParseOCSPResponseDER(responseDER)
	if err != nil {
		t.Fatalf("parse OCSP response: %v", err)
	}
	if parsed.Status != wantStatus {
		t.Fatalf("expected OCSP response status %d, got %+v", wantStatus, parsed)
	}
	if wantStatus == OCSPSuccessful {
		if err := VerifyOCSPResponseSignature(responseDER, issuer); err != nil {
			t.Fatalf("verify OCSP response signature: %v", err)
		}
	}
	if parsed.CertificateStatus != wantCertStatus || parsed.Serial != wantSerial {
		t.Fatalf("expected cert status %q serial %q, got %+v", wantCertStatus, wantSerial, parsed)
	}
	if !parsed.ThisUpdate.Equal(wantThisUpdate) || !parsed.NextUpdate.Equal(wantNextUpdate) {
		t.Fatalf("unexpected OCSP validity window: %+v", parsed)
	}
	return parsed
}

func parseTestCertificatePEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("expected certificate PEM, got block %+v", block)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return certificate
}
