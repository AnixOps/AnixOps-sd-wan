package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/policy"
	"anixops-sd-wan/internal/telemetry"
)

func TestFileRepositoryPersistsControlPlaneObjects(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "control-store.json")
	repo, err := NewFileRepository(path)
	if err != nil {
		t.Fatalf("new file repository: %v", err)
	}
	if _, err := repo.CreateTenant(ctx, domain.Tenant{ID: "tenant-a", Name: "Tenant A"}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	assertPrivateStoreFile(t, path)
	if _, err := repo.RegisterDevice(ctx, domain.Device{
		ID:       "agent-a",
		TenantID: "tenant-a",
		Kind:     domain.DeviceClient,
		Name:     "Agent A",
	}); err != nil {
		t.Fatalf("register device: %v", err)
	}
	if _, err := repo.RegisterNode(ctx, domain.Node{
		ID:       "edge-a",
		TenantID: "tenant-a",
		Role:     domain.NodeOverseasEdge,
		Region:   "hk",
		Endpoint: "old.example.com:443",
	}); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if _, err := repo.RecordNodeHeartbeat(ctx, domain.NodeHeartbeat{
		TenantID: "tenant-a",
		NodeID:   "edge-a",
		Healthy:  true,
		Endpoint: "new.example.com:443",
	}); err != nil {
		t.Fatalf("record node heartbeat: %v", err)
	}
	if _, err := repo.UpsertPolicyRule(ctx, policy.Rule{
		ID:           "ai-openai",
		TenantID:     "tenant-a",
		Priority:     100,
		DomainSuffix: "openai.com",
		Class:        policy.ClassAI,
		EgressNodeID: "jp-egress",
	}); err != nil {
		t.Fatalf("upsert policy: %v", err)
	}
	if _, err := repo.UpsertConfig(ctx, domain.ConfigBundle{
		ID:       "cfg-1",
		TenantID: "tenant-a",
		TargetID: "agent-a",
		Version:  "v1",
	}); err != nil {
		t.Fatalf("upsert config: %v", err)
	}
	if _, err := repo.RecordTelemetry(ctx, telemetry.Report{
		TenantID:    "tenant-a",
		SubjectID:   "agent-a",
		SubjectKind: telemetry.SubjectAgent,
	}); err != nil {
		t.Fatalf("record telemetry: %v", err)
	}

	reloaded, err := NewFileRepository(path)
	if err != nil {
		t.Fatalf("reload file repository: %v", err)
	}
	inventory, err := reloaded.Inventory(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if len(inventory.Devices) != 1 || inventory.Devices[0].ID != "agent-a" {
		t.Fatalf("expected persisted device, got %+v", inventory.Devices)
	}
	if len(inventory.Nodes) != 1 || inventory.Nodes[0].ID != "edge-a" || !inventory.Nodes[0].Healthy || inventory.Nodes[0].Endpoint != "new.example.com:443" {
		t.Fatalf("expected persisted healthy node, got %+v", inventory.Nodes)
	}
	if _, err := reloaded.RetireNode(ctx, "tenant-a", "edge-a"); err != nil {
		t.Fatalf("retire node: %v", err)
	}
	assertPrivateStoreFile(t, path)
	reloadedAfterRetire, err := NewFileRepository(path)
	if err != nil {
		t.Fatalf("reload after retire: %v", err)
	}
	retiredInventory, err := reloadedAfterRetire.Inventory(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("retired inventory: %v", err)
	}
	if len(retiredInventory.Nodes) != 0 {
		t.Fatalf("expected persisted retired node removal, got %+v", retiredInventory.Nodes)
	}
	configs, err := reloaded.Configs(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("configs: %v", err)
	}
	if len(configs) != 1 || configs[0].Version != "v1" {
		t.Fatalf("expected persisted config, got %+v", configs)
	}
	reports, err := reloaded.Telemetry(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("telemetry: %v", err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected persisted telemetry, got %+v", reports)
	}
}

func TestFileRepositoryBackupAndRestore(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "control-store.json")
	repo, err := NewFileRepository(path)
	if err != nil {
		t.Fatalf("new file repository: %v", err)
	}
	populateBackupRepository(t, ctx, repo)

	backupPath := filepath.Join(t.TempDir(), "backup", "control-store.backup.json")
	createdAt := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	backup, err := repo.Backup(backupPath, createdAt)
	if err != nil {
		t.Fatalf("backup repository: %v", err)
	}
	assertPrivateStoreFile(t, backupPath)
	if backup.Version != BackupVersion || !backup.CreatedAt.Equal(createdAt) {
		t.Fatalf("unexpected backup metadata: %+v", backup)
	}
	if backup.Counts.Tenants != 1 || backup.Counts.Devices != 1 || backup.Counts.Nodes != 1 || backup.Counts.Policies != 1 || backup.Counts.Configs != 1 || backup.Counts.Telemetry != 1 || backup.Counts.Audit == 0 {
		t.Fatalf("unexpected backup counts: %+v", backup.Counts)
	}

	restoredPath := filepath.Join(t.TempDir(), "restore", "control-store.json")
	if _, err := RestoreBackupFile(restoredPath, backupPath); err != nil {
		t.Fatalf("restore backup file: %v", err)
	}
	assertPrivateStoreFile(t, restoredPath)
	restored, err := NewFileRepository(restoredPath)
	if err != nil {
		t.Fatalf("reload restored file repository: %v", err)
	}
	inventory, err := restored.Inventory(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("restored inventory: %v", err)
	}
	if len(inventory.Devices) != 1 || inventory.Devices[0].ID != "agent-a" {
		t.Fatalf("expected restored device, got %+v", inventory.Devices)
	}
	policies, err := restored.PolicyRules(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("restored policies: %v", err)
	}
	if len(policies) != 1 || policies[0].ID != "ai-openai" {
		t.Fatalf("expected restored policy, got %+v", policies)
	}
	configs, err := restored.Configs(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("restored configs: %v", err)
	}
	if len(configs) != 1 || configs[0].Version != "v1" {
		t.Fatalf("expected restored config, got %+v", configs)
	}
	reports, err := restored.Telemetry(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("restored telemetry: %v", err)
	}
	if len(reports) != 1 || reports[0].SubjectID != "agent-a" {
		t.Fatalf("expected restored telemetry, got %+v", reports)
	}
}

func TestLoadBackupRejectsTamperedSnapshot(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "control-store.json")
	repo, err := NewFileRepository(path)
	if err != nil {
		t.Fatalf("new file repository: %v", err)
	}
	populateBackupRepository(t, ctx, repo)

	backupPath := filepath.Join(t.TempDir(), "backup", "control-store.backup.json")
	if _, err := repo.Backup(backupPath, time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("backup repository: %v", err)
	}
	backup, err := LoadBackup(backupPath)
	if err != nil {
		t.Fatalf("load backup before tamper: %v", err)
	}
	tenant := backup.Snapshot.Tenants["tenant-a"]
	tenant.Name = "Tampered"
	backup.Snapshot.Tenants["tenant-a"] = tenant
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		t.Fatalf("marshal tampered backup: %v", err)
	}
	if err := os.WriteFile(backupPath, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write tampered backup: %v", err)
	}
	if _, err := LoadBackup(backupPath); err == nil {
		t.Fatal("expected tampered backup snapshot to be rejected")
	}
}

func populateBackupRepository(t *testing.T, ctx context.Context, repo *FileRepository) {
	t.Helper()
	if _, err := repo.CreateTenant(ctx, domain.Tenant{ID: "tenant-a", Name: "Tenant A"}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	if _, err := repo.RegisterDevice(ctx, domain.Device{
		ID:       "agent-a",
		TenantID: "tenant-a",
		Kind:     domain.DeviceClient,
		Name:     "Agent A",
	}); err != nil {
		t.Fatalf("register device: %v", err)
	}
	if _, err := repo.RegisterNode(ctx, domain.Node{
		ID:       "edge-a",
		TenantID: "tenant-a",
		Role:     domain.NodeOverseasEdge,
		Region:   "hk",
		Endpoint: "edge.example.com:443",
	}); err != nil {
		t.Fatalf("register node: %v", err)
	}
	if _, err := repo.UpsertPolicyRule(ctx, policy.Rule{
		ID:           "ai-openai",
		TenantID:     "tenant-a",
		Priority:     100,
		DomainSuffix: "openai.com",
		Class:        policy.ClassAI,
		EgressNodeID: "jp-egress",
	}); err != nil {
		t.Fatalf("upsert policy: %v", err)
	}
	if _, err := repo.UpsertConfig(ctx, domain.ConfigBundle{
		ID:       "cfg-1",
		TenantID: "tenant-a",
		TargetID: "agent-a",
		Version:  "v1",
	}); err != nil {
		t.Fatalf("upsert config: %v", err)
	}
	if _, err := repo.RecordTelemetry(ctx, telemetry.Report{
		TenantID:    "tenant-a",
		SubjectID:   "agent-a",
		SubjectKind: telemetry.SubjectAgent,
	}); err != nil {
		t.Fatalf("record telemetry: %v", err)
	}
}

func assertPrivateStoreFile(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not reliable on Windows")
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat store dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("expected private store dir mode 700, got %o", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat store file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected private store file mode 600, got %o", got)
	}
}
