package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"anixops-sd-wan/internal/agent"
	"anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/transport"
)

func TestNewAgentServiceCanDisableTransportRuntime(t *testing.T) {
	svc, err := newAgentService(config.Default(), nil, nil, false, "invalid", 0, "")
	if err != nil {
		t.Fatalf("new service without transport runtime: %v", err)
	}
	if svc.Snapshot().Protocol != transport.ProtocolHysteria2 {
		t.Fatalf("expected default selection, got %s", svc.Snapshot().Protocol)
	}
}

func TestNewAgentServiceConfiguresTransportRuntime(t *testing.T) {
	svc, err := newAgentService(config.Default(), nil, nil, true, string(transport.ProtocolReality), time.Second, "/tmp/anixops")
	if err != nil {
		t.Fatalf("new service with transport runtime: %v", err)
	}
	if svc.Snapshot().Protocol != transport.ProtocolReality {
		t.Fatalf("expected runtime active protocol, got %s", svc.Snapshot().Protocol)
	}
}

func TestNewAgentServiceRejectsUnknownTransportRuntimeProtocol(t *testing.T) {
	if _, err := newAgentService(config.Default(), nil, nil, true, "unknown", time.Second, "/tmp/anixops"); err == nil {
		t.Fatal("expected unknown transport protocol to be rejected")
	}
}

func TestApproveConfigSigningKeyRequestFileWritesApproval(t *testing.T) {
	signer, err := config.NewConfigSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	key, err := config.NewSigningPublicKey(signer.PublicKey(), time.Date(2026, 5, 12, 2, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new signing public key: %v", err)
	}
	request, err := config.NewSigningKeyApprovalRequest(key, "control-admin", time.Date(2026, 5, 12, 3, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new signing key approval request: %v", err)
	}
	request.Source = "control-api"
	request.Reason = "planned rotation"
	requestPath := filepath.Join(t.TempDir(), "request.json")
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if err := os.WriteFile(requestPath, encoded, 0o600); err != nil {
		t.Fatalf("write request: %v", err)
	}
	approvalPath := filepath.Join(t.TempDir(), "state", "approval.json")
	approvedAt := time.Date(2026, 5, 12, 4, 0, 0, 0, time.UTC)

	approval, err := approveConfigSigningKeyRequestFile(requestPath, approvalPath, "operator-a", "approved after out-of-band check", approvedAt)
	if err != nil {
		t.Fatalf("approve request file: %v", err)
	}
	if approval.ApprovedBy != "operator-a" || !approval.ApprovedAt.Equal(approvedAt) {
		t.Fatalf("unexpected approval metadata: %+v", approval)
	}
	if approval.RequestedBy != "control-admin" || approval.Source != "control-api" || approval.Note != "approved after out-of-band check" {
		t.Fatalf("expected request metadata and note to be recorded, got %+v", approval)
	}
	loaded, err := agent.LoadSigningKeyApproval(approvalPath)
	if err != nil {
		t.Fatalf("load written approval: %v", err)
	}
	if err := loaded.ValidateSigningKey(key); err != nil {
		t.Fatalf("written approval should validate signing key: %v", err)
	}
}
