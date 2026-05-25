package cert

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileRevocationListPublisherWritesPEMAndManifest(t *testing.T) {
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
	if _, err := authority.Revoke(issued.Record.Serial, now.Add(time.Minute)); err != nil {
		t.Fatalf("revoke certificate: %v", err)
	}
	list, err := authority.RevocationListByTenant("tenant-a", now.Add(2*time.Minute), time.Hour)
	if err != nil {
		t.Fatalf("build crl: %v", err)
	}

	publisher, err := NewFileRevocationListPublisher(t.TempDir())
	if err != nil {
		t.Fatalf("new publisher: %v", err)
	}
	published, err := publisher.PublishRevocationList(context.Background(), list)
	if err != nil {
		t.Fatalf("publish crl: %v", err)
	}
	if published.TenantID != "tenant-a" || published.RevokedCount != 1 {
		t.Fatalf("unexpected published metadata: %+v", published)
	}

	crlPEM, err := os.ReadFile(published.CRLPath)
	if err != nil {
		t.Fatalf("read published crl pem: %v", err)
	}
	if !bytes.Equal(crlPEM, list.CRLPEM) {
		t.Fatal("expected published crl pem to match generated crl")
	}
	if _, err := ParseRevocationListPEM(crlPEM); err != nil {
		t.Fatalf("published crl should parse: %v", err)
	}

	var manifest PublishedRevocationList
	data, err := os.ReadFile(published.ManifestPath)
	if err != nil {
		t.Fatalf("read crl manifest: %v", err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("manifest should be json: %v", err)
	}
	sum := sha256.Sum256(list.CRLPEM)
	if manifest.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("expected manifest sha256 to match CRL PEM, got %s", manifest.SHA256)
	}
	if filepath.Base(published.CRLPath) != "tenant-a.crl.pem" || filepath.Base(published.ManifestPath) != "tenant-a.crl.json" {
		t.Fatalf("unexpected published paths: %+v", published)
	}

	verified, err := VerifyPublishedRevocationList(publisher.Dir, "tenant-a")
	if err != nil {
		t.Fatalf("verify published crl: %v", err)
	}
	if verified.Manifest.SHA256 != manifest.SHA256 || !bytes.Equal(verified.CRLPEM, list.CRLPEM) || verified.Parsed == nil {
		t.Fatalf("unexpected verified crl: %+v", verified.Manifest)
	}
}

func TestFileRevocationListPublisherRejectsUnsafeTenantFileName(t *testing.T) {
	publisher, err := NewFileRevocationListPublisher(t.TempDir())
	if err != nil {
		t.Fatalf("new publisher: %v", err)
	}
	_, err = publisher.PublishRevocationList(context.Background(), RevocationList{
		TenantID: "../tenant-a",
		CRLPEM:   validEmptyCRLPEM(t),
	})
	if err == nil {
		t.Fatal("expected unsafe tenant id to be rejected")
	}
	if !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("expected unsafe tenant error, got %v", err)
	}
}

func TestParseRevocationListPEMRejectsInvalidPEM(t *testing.T) {
	if _, err := ParseRevocationListPEM([]byte("not pem")); err == nil {
		t.Fatal("expected invalid crl pem to be rejected")
	}
}

func TestVerifyPublishedRevocationListRejectsTamperedPEM(t *testing.T) {
	dir := t.TempDir()
	publisher, err := NewFileRevocationListPublisher(dir)
	if err != nil {
		t.Fatalf("new publisher: %v", err)
	}
	if _, err := publisher.PublishRevocationList(context.Background(), RevocationList{
		TenantID: "tenant-a",
		Issuer:   "issuer",
		CRLPEM:   validEmptyCRLPEM(t),
	}); err != nil {
		t.Fatalf("publish crl: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tenant-a.crl.pem"), []byte("tampered"), 0o644); err != nil {
		t.Fatalf("tamper crl: %v", err)
	}
	if _, err := VerifyPublishedRevocationList(dir, "tenant-a"); err == nil {
		t.Fatal("expected tampered crl to be rejected")
	}
}

func TestVerifyPublishedRevocationListRejectsManifestMismatch(t *testing.T) {
	dir := t.TempDir()
	publisher, err := NewFileRevocationListPublisher(dir)
	if err != nil {
		t.Fatalf("new publisher: %v", err)
	}
	published, err := publisher.PublishRevocationList(context.Background(), RevocationList{
		TenantID: "tenant-a",
		Issuer:   "issuer",
		CRLPEM:   validEmptyCRLPEM(t),
	})
	if err != nil {
		t.Fatalf("publish crl: %v", err)
	}
	data, err := os.ReadFile(published.ManifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest PublishedRevocationList
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	manifest.RevokedCount = 99
	tampered, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal tampered manifest: %v", err)
	}
	if err := os.WriteFile(published.ManifestPath, tampered, 0o644); err != nil {
		t.Fatalf("write tampered manifest: %v", err)
	}
	if _, err := VerifyPublishedRevocationList(dir, "tenant-a"); err == nil {
		t.Fatal("expected manifest mismatch to be rejected")
	}
}

func TestVerifyPublishedRevocationListHTTP(t *testing.T) {
	dir := t.TempDir()
	publisher, err := NewFileRevocationListPublisher(dir)
	if err != nil {
		t.Fatalf("new publisher: %v", err)
	}
	if _, err := publisher.PublishRevocationList(context.Background(), RevocationList{
		TenantID: "tenant-a",
		Issuer:   "issuer",
		CRLPEM:   validEmptyCRLPEM(t),
	}); err != nil {
		t.Fatalf("publish crl: %v", err)
	}
	client := &http.Client{Transport: handlerTransport{handler: http.FileServer(http.Dir(dir))}}

	verified, err := VerifyPublishedRevocationListHTTP(context.Background(), client, "http://crl.test", "tenant-a")
	if err != nil {
		t.Fatalf("verify http published crl: %v", err)
	}
	if verified.Manifest.TenantID != "tenant-a" || verified.Parsed == nil || len(verified.CRLPEM) == 0 {
		t.Fatalf("unexpected http verified crl: %+v", verified.Manifest)
	}
}

func TestVerifyPublishedRevocationListHTTPRejectsTamperedManifest(t *testing.T) {
	dir := t.TempDir()
	publisher, err := NewFileRevocationListPublisher(dir)
	if err != nil {
		t.Fatalf("new publisher: %v", err)
	}
	published, err := publisher.PublishRevocationList(context.Background(), RevocationList{
		TenantID: "tenant-a",
		Issuer:   "issuer",
		CRLPEM:   validEmptyCRLPEM(t),
	})
	if err != nil {
		t.Fatalf("publish crl: %v", err)
	}
	data, err := os.ReadFile(published.ManifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest PublishedRevocationList
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	manifest.SHA256 = strings.Repeat("0", 64)
	tampered, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal tampered manifest: %v", err)
	}
	if err := os.WriteFile(published.ManifestPath, tampered, 0o644); err != nil {
		t.Fatalf("write tampered manifest: %v", err)
	}
	client := &http.Client{Transport: handlerTransport{handler: http.FileServer(http.Dir(dir))}}

	if _, err := VerifyPublishedRevocationListHTTP(context.Background(), client, "http://crl.test", "tenant-a"); err == nil {
		t.Fatal("expected tampered http manifest to be rejected")
	}
}

type handlerTransport struct {
	handler http.Handler
}

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}

func validEmptyCRLPEM(t *testing.T) []byte {
	t.Helper()

	now := time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC)
	authority, err := NewAuthority("anixops-test-ca", now)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	list, err := authority.RevocationListByTenant("tenant-a", now, time.Hour)
	if err != nil {
		t.Fatalf("build empty crl: %v", err)
	}
	return list.CRLPEM
}
