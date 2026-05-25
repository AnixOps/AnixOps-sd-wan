package config

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anixops-sd-wan/internal/domain"
)

func TestConfigSignerSignsAndVerifiesBundle(t *testing.T) {
	signer, err := NewConfigSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	bundle := domain.ConfigBundle{
		ID:        "cfg-1",
		TenantID:  "tenant-a",
		TargetID:  "agent-a",
		Version:   "v1",
		Values:    map[string]string{"transport": "hysteria2"},
		CreatedAt: time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC),
	}

	signed, err := signer.Sign(bundle, time.Date(2026, 5, 12, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	verifier, err := NewConfigVerifier(signer.PublicKey())
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := verifier.Verify(signed); err != nil {
		t.Fatalf("verify signed bundle: %v", err)
	}
}

func TestSigningPublicKeyBuildsVerifier(t *testing.T) {
	signer, err := NewConfigSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	key, err := NewSigningPublicKey(signer.PublicKey(), time.Date(2026, 5, 12, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new signing public key: %v", err)
	}
	verifier, err := NewConfigVerifierFromSigningKey(key)
	if err != nil {
		t.Fatalf("new verifier from key: %v", err)
	}
	signed, err := signer.Sign(domain.ConfigBundle{
		ID:       "cfg-1",
		TenantID: "tenant-a",
		TargetID: "agent-a",
		Version:  "v1",
		Values:   map[string]string{"transport": "hysteria2"},
	}, time.Now())
	if err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	if err := verifier.Verify(signed); err != nil {
		t.Fatalf("verify signed bundle: %v", err)
	}
}

func TestSigningPublicKeySHA256Fingerprint(t *testing.T) {
	signer, err := NewConfigSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	key, err := NewSigningPublicKey(signer.PublicKey(), time.Date(2026, 5, 12, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new signing public key: %v", err)
	}
	fingerprint, err := key.SHA256Fingerprint()
	if err != nil {
		t.Fatalf("fingerprint signing key: %v", err)
	}
	if len(fingerprint) != 64 {
		t.Fatalf("expected sha256 hex fingerprint length 64, got %q", fingerprint)
	}
	if key.SHA256FingerprintHex != fingerprint {
		t.Fatalf("expected public key envelope fingerprint %q, got %q", fingerprint, key.SHA256FingerprintHex)
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		t.Fatalf("fingerprint should be hex: %v", err)
	}
}

func TestSigningKeyApprovalRequestRoundTrip(t *testing.T) {
	signer, err := NewConfigSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	rotatedAt := time.Date(2026, 5, 12, 2, 0, 0, 0, time.UTC)
	key, err := NewSigningPublicKey(signer.PublicKey(), rotatedAt)
	if err != nil {
		t.Fatalf("new signing public key: %v", err)
	}
	requestedAt := time.Date(2026, 5, 12, 3, 0, 0, 0, time.UTC)
	request, err := NewSigningKeyApprovalRequest(key, "operator-a", requestedAt)
	if err != nil {
		t.Fatalf("new approval request: %v", err)
	}
	request.Source = "control-api"
	request.Reason = "rotation"
	if request.Version != SigningKeyApprovalRequestVersion || request.Kind != SigningKeyApprovalRequestKind {
		t.Fatalf("unexpected request metadata: %+v", request)
	}
	if request.RequestedBy != "operator-a" || !request.RequestedAt.Equal(requestedAt) {
		t.Fatalf("unexpected requester metadata: %+v", request)
	}

	path := filepath.Join(t.TempDir(), "approval-request.json")
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal approval request: %v", err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write approval request: %v", err)
	}
	loaded, err := LoadSigningKeyApprovalRequest(path)
	if err != nil {
		t.Fatalf("load approval request: %v", err)
	}
	loadedKey, err := loaded.SigningPublicKey()
	if err != nil {
		t.Fatalf("approval request signing key: %v", err)
	}
	if loadedKey.PublicKey != key.PublicKey || loadedKey.SHA256FingerprintHex != key.SHA256FingerprintHex {
		t.Fatalf("loaded request changed key: %+v want %+v", loadedKey, key)
	}
}

func TestSigningKeyApprovalRequestRejectsTamperedFingerprint(t *testing.T) {
	signer, err := NewConfigSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	key, err := NewSigningPublicKey(signer.PublicKey(), time.Date(2026, 5, 12, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new signing public key: %v", err)
	}
	request, err := NewSigningKeyApprovalRequest(key, "operator-a", time.Date(2026, 5, 12, 3, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new approval request: %v", err)
	}
	request.SHA256FingerprintHex = strings.Repeat("0", 64)

	if _, err := request.SigningPublicKey(); err == nil {
		t.Fatal("expected tampered approval request fingerprint to fail")
	}
}

func TestConfigSignerPrivateKeyPEMRoundTrip(t *testing.T) {
	signer, err := NewConfigSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	pemBytes, err := signer.PrivateKeyPEM()
	if err != nil {
		t.Fatalf("private key pem: %v", err)
	}
	loaded, err := NewConfigSignerFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("load signer from pem: %v", err)
	}
	if string(loaded.PublicKey()) != string(signer.PublicKey()) {
		t.Fatal("expected loaded signer to preserve public key")
	}

	signed, err := loaded.Sign(domain.ConfigBundle{
		ID:       "cfg-1",
		TenantID: "tenant-a",
		TargetID: "agent-a",
		Version:  "v1",
		Values:   map[string]string{"transport": "hysteria2"},
	}, time.Now())
	if err != nil {
		t.Fatalf("sign with loaded key: %v", err)
	}
	verifier, err := NewConfigVerifier(signer.PublicKey())
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := verifier.Verify(signed); err != nil {
		t.Fatalf("verify loaded-key signature: %v", err)
	}
}

func TestConfigSignerRejectsTamperedBundle(t *testing.T) {
	signer, err := NewConfigSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	signed, err := signer.Sign(domain.ConfigBundle{
		ID:       "cfg-1",
		TenantID: "tenant-a",
		TargetID: "agent-a",
		Version:  "v1",
		Values:   map[string]string{"transport": "hysteria2"},
	}, time.Now())
	if err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	signed.Bundle.Values["transport"] = "reality"

	if err := signer.Verify(signed); err == nil {
		t.Fatal("expected signature verification to fail after tampering")
	}
}
