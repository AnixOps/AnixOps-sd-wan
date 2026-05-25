package agent

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	configsign "anixops-sd-wan/internal/config"
)

func TestSigningKeyApprovalRoundTripBuildsTrustPolicy(t *testing.T) {
	key := testSigningPublicKey(t)
	approvedAt := time.Date(2026, 5, 12, 3, 0, 0, 0, time.UTC)
	approval, err := NewSigningKeyApproval(key, "operator-a", approvedAt)
	if err != nil {
		t.Fatalf("new signing key approval: %v", err)
	}
	if approval.Version != SigningKeyApprovalVersion || approval.ApprovedBy != "operator-a" {
		t.Fatalf("unexpected approval metadata: %+v", approval)
	}

	path := filepath.Join(t.TempDir(), "trust", "signing-key-approval.json")
	if err := SaveSigningKeyApproval(path, approval); err != nil {
		t.Fatalf("save signing key approval: %v", err)
	}
	loaded, err := LoadSigningKeyApproval(path)
	if err != nil {
		t.Fatalf("load signing key approval: %v", err)
	}
	policy, err := loaded.TrustPolicy()
	if err != nil {
		t.Fatalf("approval trust policy: %v", err)
	}
	if err := policy.Validate(key); err != nil {
		t.Fatalf("approved key should satisfy policy: %v", err)
	}
}

func TestSigningKeyApprovalFromRequestCarriesApprovalMetadata(t *testing.T) {
	key := testSigningPublicKey(t)
	requestedAt := time.Date(2026, 5, 12, 2, 0, 0, 0, time.UTC)
	request, err := configsign.NewSigningKeyApprovalRequest(key, "control-admin", requestedAt)
	if err != nil {
		t.Fatalf("new signing key approval request: %v", err)
	}
	request.Source = "control-api"
	request.Reason = "planned rotation"
	approvedAt := time.Date(2026, 5, 12, 3, 0, 0, 0, time.UTC)

	approval, err := NewSigningKeyApprovalFromRequest(request, "operator-a", approvedAt)
	if err != nil {
		t.Fatalf("approve signing key request: %v", err)
	}
	if approval.ApprovedBy != "operator-a" || !approval.ApprovedAt.Equal(approvedAt) {
		t.Fatalf("unexpected approval metadata: %+v", approval)
	}
	if approval.Source != "control-api" || approval.Note != "planned rotation" {
		t.Fatalf("expected request source/reason to be carried, got %+v", approval)
	}
	if approval.RequestedBy != "control-admin" || approval.RequestedAt == nil || !approval.RequestedAt.Equal(requestedAt) {
		t.Fatalf("expected request metadata to be carried, got %+v", approval)
	}
	if err := approval.ValidateSigningKey(key); err != nil {
		t.Fatalf("approved request key should validate: %v", err)
	}
}

func TestSigningKeyApprovalRejectsTamperedFingerprint(t *testing.T) {
	key := testSigningPublicKey(t)
	approval, err := NewSigningKeyApproval(key, "operator-a", time.Date(2026, 5, 12, 3, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new signing key approval: %v", err)
	}
	approval.SHA256FingerprintHex = strings.Repeat("0", 64)

	if _, err := approval.SigningPublicKey(); err == nil {
		t.Fatal("expected tampered fingerprint to fail")
	}
}

func TestSigningKeyApprovalRejectsUnapprovedFetchedKey(t *testing.T) {
	approvedKey := testSigningPublicKey(t)
	approval, err := NewSigningKeyApproval(approvedKey, "operator-a", time.Date(2026, 5, 12, 3, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new signing key approval: %v", err)
	}
	signer, err := configsign.NewConfigSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	otherKey, err := configsign.NewSigningPublicKey(signer.PublicKey(), time.Date(2026, 5, 12, 4, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new other signing key: %v", err)
	}

	if err := approval.ValidateSigningKey(otherKey); err == nil {
		t.Fatal("expected unapproved fetched key to fail")
	}
}

func TestSigningKeyApprovalRequiresApproverAndTime(t *testing.T) {
	key := testSigningPublicKey(t)
	if _, err := NewSigningKeyApproval(key, "", time.Date(2026, 5, 12, 3, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected missing approver to fail")
	}
	approval, err := NewSigningKeyApproval(key, "operator-a", time.Date(2026, 5, 12, 3, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new signing key approval: %v", err)
	}
	approval.ApprovedAt = time.Time{}
	if _, err := approval.SigningPublicKey(); err == nil {
		t.Fatal("expected missing approval time to fail")
	}
}
