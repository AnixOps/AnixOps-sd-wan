package store

import (
	"context"
	"testing"

	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/policy"
	"anixops-sd-wan/internal/telemetry"
)

func TestMemoryStoreKeepsTenantsIsolated(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	if _, err := store.CreateTenant(ctx, domain.Tenant{ID: "tenant-a", Name: "Tenant A"}); err != nil {
		t.Fatalf("create tenant a: %v", err)
	}
	if _, err := store.CreateTenant(ctx, domain.Tenant{ID: "tenant-b", Name: "Tenant B"}); err != nil {
		t.Fatalf("create tenant b: %v", err)
	}
	if _, err := store.RegisterDevice(ctx, domain.Device{
		ID:       "device-a",
		TenantID: "tenant-a",
		Kind:     domain.DeviceClient,
		Name:     "Device A",
		Platform: "linux/amd64",
	}); err != nil {
		t.Fatalf("register device: %v", err)
	}

	inventoryA, err := store.Inventory(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("inventory tenant a: %v", err)
	}
	inventoryB, err := store.Inventory(ctx, "tenant-b")
	if err != nil {
		t.Fatalf("inventory tenant b: %v", err)
	}

	if len(inventoryA.Devices) != 1 {
		t.Fatalf("expected tenant a to have one device, got %d", len(inventoryA.Devices))
	}
	if len(inventoryB.Devices) != 0 {
		t.Fatalf("expected tenant b to have no devices, got %d", len(inventoryB.Devices))
	}
}

func TestMemoryStoreRecordsSanitizedTelemetryAndAudit(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	if _, err := store.CreateTenant(ctx, domain.Tenant{ID: "tenant-a", Name: "Tenant A"}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	report, err := store.RecordTelemetry(ctx, telemetry.Report{
		TenantID:    "tenant-a",
		SubjectID:   "agent-a",
		SubjectKind: telemetry.SubjectAgent,
		Metrics: map[string]float64{
			"rtt_ms": 20,
		},
		Logs: []telemetry.LogRecord{{
			Level:   "info",
			Message: "connected",
			Fields:  map[string]string{"token": "secret"},
		}},
	})
	if err != nil {
		t.Fatalf("record telemetry: %v", err)
	}

	if report.Logs[0].Fields["token"] != "[redacted]" {
		t.Fatalf("expected sanitized telemetry token")
	}
	recorded, err := store.RecordAuditEvent(ctx, domain.AuditEvent{
		TenantID:   "tenant-a",
		Actor:      "admin-a",
		Action:     "config_signing_key.rotate",
		ObjectType: "config_signing_key",
		ObjectID:   "fingerprint-a",
		Message:    "rotated config signing key",
	})
	if err != nil {
		t.Fatalf("record explicit audit event: %v", err)
	}
	if recorded.ID == "" || recorded.CreatedAt.IsZero() {
		t.Fatalf("expected explicit audit event id/time, got %+v", recorded)
	}
	events, err := store.AuditEvents(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("audit events: %v", err)
	}
	if len(events) < 3 {
		t.Fatalf("expected tenant create, telemetry and explicit audit events, got %d", len(events))
	}
}

func TestMemoryStoreRecordsNodeHeartbeat(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	if _, err := store.CreateTenant(ctx, domain.Tenant{ID: "tenant-a", Name: "Tenant A"}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := store.RegisterNode(ctx, domain.Node{
		ID:       "edge-a",
		TenantID: "tenant-a",
		Role:     domain.NodeOverseasEdge,
		Region:   "hk",
		Endpoint: "old.example.com:443",
		Healthy:  false,
	}); err != nil {
		t.Fatalf("register node: %v", err)
	}
	updated, err := store.RecordNodeHeartbeat(ctx, domain.NodeHeartbeat{
		TenantID: "tenant-a",
		NodeID:   "edge-a",
		Healthy:  true,
		Endpoint: "new.example.com:443",
	})
	if err != nil {
		t.Fatalf("record node heartbeat: %v", err)
	}
	if !updated.Healthy || updated.Endpoint != "new.example.com:443" {
		t.Fatalf("expected healthy node with updated endpoint, got %+v", updated)
	}
	inventory, err := store.Inventory(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if len(inventory.Nodes) != 1 || !inventory.Nodes[0].Healthy || inventory.Nodes[0].Endpoint != "new.example.com:443" {
		t.Fatalf("expected heartbeat to update inventory node, got %+v", inventory.Nodes)
	}
}

func TestMemoryStoreRetiresNode(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	if _, err := store.CreateTenant(ctx, domain.Tenant{ID: "tenant-a", Name: "Tenant A"}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := store.RegisterNode(ctx, domain.Node{
		ID:       "edge-a",
		TenantID: "tenant-a",
		Role:     domain.NodeOverseasEdge,
		Region:   "hk",
		Endpoint: "edge.example.com:443",
		Healthy:  true,
	}); err != nil {
		t.Fatalf("register node: %v", err)
	}
	retired, err := store.RetireNode(ctx, "tenant-a", "edge-a")
	if err != nil {
		t.Fatalf("retire node: %v", err)
	}
	if retired.ID != "edge-a" || retired.Healthy {
		t.Fatalf("expected retired unhealthy node, got %+v", retired)
	}
	inventory, err := store.Inventory(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if len(inventory.Nodes) != 0 {
		t.Fatalf("expected retired node to be removed from inventory, got %+v", inventory.Nodes)
	}
	events, err := store.AuditEvents(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("audit events: %v", err)
	}
	found := false
	for _, event := range events {
		if event.Action == "node.retire" && event.ObjectType == "node" && event.ObjectID == "edge-a" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected node retirement audit event, got %+v", events)
	}
}

func TestMemoryStoreEvaluatesTenantPolicy(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	if _, err := store.CreateTenant(ctx, domain.Tenant{ID: "tenant-a", Name: "Tenant A"}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := store.UpsertPolicyRule(ctx, policy.Rule{
		ID:           "ai",
		TenantID:     "tenant-a",
		Priority:     100,
		DomainSuffix: "openai.com",
		Class:        policy.ClassAI,
		EgressNodeID: "jp-egress",
	}); err != nil {
		t.Fatalf("upsert policy: %v", err)
	}

	decision, err := store.EvaluatePolicy(ctx, policy.Request{TenantID: "tenant-a", Domain: "api.openai.com", Class: policy.ClassAI})
	if err != nil {
		t.Fatalf("evaluate policy: %v", err)
	}
	if decision.EgressNodeID != "jp-egress" {
		t.Fatalf("expected jp-egress, got %+v", decision)
	}
}

func TestMemoryStoreTracksConfigVersions(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()

	if _, err := store.CreateTenant(ctx, domain.Tenant{ID: "tenant-a", Name: "Tenant A"}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := store.UpsertConfig(ctx, domain.ConfigBundle{
		ID:       "cfg-1",
		TenantID: "tenant-a",
		TargetID: "agent-a",
		Version:  "v1",
		Values:   map[string]string{"transport": "hysteria2"},
	}); err != nil {
		t.Fatalf("upsert config: %v", err)
	}

	configs, err := store.Configs(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("configs: %v", err)
	}
	if len(configs) != 1 || configs[0].Version != "v1" {
		t.Fatalf("expected v1 config, got %+v", configs)
	}
}
