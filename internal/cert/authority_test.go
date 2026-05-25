package cert

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestAuthorityIssuesAndRevokesCertificate(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}

	issued, err := authority.Issue(Identity{
		TenantID: "tenant-a",
		DeviceID: "device-a",
		Role:     "agent",
	}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	if len(issued.Record.CertPEM) == 0 {
		t.Fatal("expected certificate pem")
	}
	if len(issued.PrivateKeyPEM) == 0 {
		t.Fatal("expected private key pem to be returned to caller")
	}

	revoked, err := authority.Revoke(issued.Record.Serial, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("revoke certificate: %v", err)
	}
	if !revoked.Revoked {
		t.Fatal("expected certificate to be revoked")
	}
}

func TestAuthorityCertificateStatus(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	issued, err := authority.Issue(Identity{
		TenantID: "tenant-a",
		DeviceID: "device-a",
		Role:     "agent",
	}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}

	status, err := authority.CertificateStatus("tenant-a", issued.Record.Serial, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("certificate status: %v", err)
	}
	if status.State != CertificateGood || status.Revoked {
		t.Fatalf("expected good status, got %+v", status)
	}

	if _, err := authority.Revoke(issued.Record.Serial, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("revoke certificate: %v", err)
	}
	status, err = authority.CertificateStatus("tenant-a", issued.Record.Serial, now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("revoked certificate status: %v", err)
	}
	if status.State != CertificateRevoked || !status.Revoked || status.RevokedAt.IsZero() {
		t.Fatalf("expected revoked status, got %+v", status)
	}

	status, err = authority.CertificateStatus("tenant-a", "missing", now)
	if err != nil {
		t.Fatalf("missing certificate status: %v", err)
	}
	if status.State != CertificateUnknown {
		t.Fatalf("expected unknown status, got %+v", status)
	}
}

func TestAuthorityCertificateStatusReportsValidityWindow(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	issued, err := authority.Issue(Identity{
		TenantID: "tenant-a",
		DeviceID: "device-a",
		Role:     "agent",
	}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}

	status, err := authority.CertificateStatus("tenant-a", issued.Record.Serial, now.Add(-time.Minute))
	if err != nil {
		t.Fatalf("not-yet-valid certificate status: %v", err)
	}
	if status.State != CertificateNotYetValid {
		t.Fatalf("expected not-yet-valid status, got %+v", status)
	}
	status, err = authority.CertificateStatus("tenant-a", issued.Record.Serial, now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("expired certificate status: %v", err)
	}
	if status.State != CertificateExpired {
		t.Fatalf("expected expired status, got %+v", status)
	}
}

func TestAuthorityDoesNotStorePrivateKeysInRecords(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}

	issued, err := authority.Issue(Identity{
		TenantID: "tenant-a",
		DeviceID: "device-a",
		Role:     "agent",
	}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	record, exists := authority.Record(issued.Record.Serial)
	if !exists {
		t.Fatal("expected issued record")
	}
	if bytes.Contains(record.CertPEM, []byte("PRIVATE KEY")) {
		t.Fatal("record certificate pem should not contain private key material")
	}
}

func TestAuthorityRotatesCertificateAndTracksRevocation(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	issued, err := authority.Issue(Identity{
		TenantID: "tenant-a",
		DeviceID: "device-a",
		Role:     "agent",
	}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}

	rotated, err := authority.Rotate(issued.Record.Serial, 2*time.Hour, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("rotate certificate: %v", err)
	}
	if rotated.Record.Serial == issued.Record.Serial {
		t.Fatal("expected rotation to issue a new serial")
	}
	old, exists := authority.Record(issued.Record.Serial)
	if !exists {
		t.Fatal("expected old certificate record")
	}
	if !old.Revoked {
		t.Fatal("expected old certificate to be revoked")
	}
	revoked := authority.RevokedRecordsByTenant("tenant-a")
	if len(revoked) != 1 || revoked[0].Serial != issued.Record.Serial {
		t.Fatalf("expected revoked old serial, got %+v", revoked)
	}
}

func TestAuthorityExportsAndLoadsCAState(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	bundle, err := authority.ExportCA()
	if err != nil {
		t.Fatalf("export ca: %v", err)
	}

	loaded, err := NewAuthorityFromPEM(bundle.CertificatePEM, bundle.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("load authority: %v", err)
	}
	if !bytes.Equal(loaded.CAPEM(), authority.CAPEM()) {
		t.Fatal("expected loaded CA certificate to match exported CA")
	}
	issued, err := loaded.Issue(Identity{
		TenantID: "tenant-a",
		DeviceID: "device-a",
		Role:     "agent",
	}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue with loaded authority: %v", err)
	}
	if issued.Record.Serial == "" {
		t.Fatal("expected issued certificate from loaded authority")
	}
	if _, err := loaded.Revoke(issued.Record.Serial, now.Add(time.Minute)); err != nil {
		t.Fatalf("revoke loaded-authority certificate: %v", err)
	}
	revocationList, err := loaded.RevocationListByTenant("tenant-a", now.Add(2*time.Minute), time.Hour)
	if err != nil {
		t.Fatalf("loaded authority revocation list: %v", err)
	}
	if len(revocationList.CRLPEM) == 0 {
		t.Fatal("expected loaded authority to build CRL PEM")
	}
}

func TestAuthorityBuildsTenantRevocationListPEM(t *testing.T) {
	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	tenantA, err := authority.Issue(Identity{
		TenantID: "tenant-a",
		DeviceID: "device-a",
		Role:     "agent",
	}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue tenant-a certificate: %v", err)
	}
	tenantB, err := authority.Issue(Identity{
		TenantID: "tenant-b",
		DeviceID: "device-b",
		Role:     "agent",
	}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue tenant-b certificate: %v", err)
	}
	if _, err := authority.Revoke(tenantA.Record.Serial, now.Add(time.Minute)); err != nil {
		t.Fatalf("revoke tenant-a certificate: %v", err)
	}
	if _, err := authority.Revoke(tenantB.Record.Serial, now.Add(time.Minute)); err != nil {
		t.Fatalf("revoke tenant-b certificate: %v", err)
	}

	list, err := authority.RevocationListByTenant("tenant-a", now.Add(2*time.Minute), time.Hour)
	if err != nil {
		t.Fatalf("revocation list: %v", err)
	}
	if list.TenantID != "tenant-a" || list.Issuer != "anixops-test-ca" {
		t.Fatalf("unexpected revocation list metadata: %+v", list)
	}
	if len(list.Records) != 1 || list.Records[0].Serial != tenantA.Record.Serial {
		t.Fatalf("expected tenant-a revoked serial only, got %+v", list.Records)
	}
	if !list.NextUpdate.Equal(now.Add(62 * time.Minute)) {
		t.Fatalf("expected next update one hour after generation, got %s", list.NextUpdate)
	}

	block, _ := pem.Decode(list.CRLPEM)
	if block == nil || block.Type != "X509 CRL" {
		t.Fatalf("expected X509 CRL PEM, got block %+v", block)
	}
	parsed, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("parse crl: %v", err)
	}
	caBlock, _ := pem.Decode(authority.CAPEM())
	if caBlock == nil {
		t.Fatal("expected CA PEM block")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	if err := parsed.CheckSignatureFrom(caCert); err != nil {
		t.Fatalf("verify crl signature: %v", err)
	}
	if len(parsed.RevokedCertificates) != 1 || parsed.RevokedCertificates[0].SerialNumber.String() != tenantA.Record.Serial {
		t.Fatalf("expected tenant-a serial in CRL only, got %+v", parsed.RevokedCertificates)
	}
}
