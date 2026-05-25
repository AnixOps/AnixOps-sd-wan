package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/policy"
	"anixops-sd-wan/internal/telemetry"
)

type Snapshot struct {
	Tenants   map[string]domain.Tenant                  `json:"tenants"`
	Devices   map[string]map[string]domain.Device       `json:"devices"`
	Nodes     map[string]map[string]domain.Node         `json:"nodes"`
	Policies  map[string]map[string]policy.Rule         `json:"policies"`
	Configs   map[string]map[string]domain.ConfigBundle `json:"configs"`
	Telemetry map[string][]telemetry.Report             `json:"telemetry"`
	Audit     map[string][]domain.AuditEvent            `json:"audit"`
}

type FileRepository struct {
	*Memory
	path string
}

func NewFileRepository(path string) (*FileRepository, error) {
	if path == "" {
		return nil, fmt.Errorf("store file path is required")
	}
	memory := NewMemory()
	if snapshot, err := loadSnapshot(path); err == nil {
		memory = NewMemoryFromSnapshot(snapshot)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return &FileRepository{Memory: memory, path: path}, nil
}

func (r *FileRepository) CreateTenant(ctx context.Context, tenant domain.Tenant) (domain.Tenant, error) {
	created, err := r.Memory.CreateTenant(ctx, tenant)
	if err != nil {
		return domain.Tenant{}, err
	}
	return created, r.save()
}

func (r *FileRepository) RegisterDevice(ctx context.Context, device domain.Device) (domain.Device, error) {
	created, err := r.Memory.RegisterDevice(ctx, device)
	if err != nil {
		return domain.Device{}, err
	}
	return created, r.save()
}

func (r *FileRepository) RegisterNode(ctx context.Context, node domain.Node) (domain.Node, error) {
	created, err := r.Memory.RegisterNode(ctx, node)
	if err != nil {
		return domain.Node{}, err
	}
	return created, r.save()
}

func (r *FileRepository) RecordNodeHeartbeat(ctx context.Context, heartbeat domain.NodeHeartbeat) (domain.Node, error) {
	updated, err := r.Memory.RecordNodeHeartbeat(ctx, heartbeat)
	if err != nil {
		return domain.Node{}, err
	}
	return updated, r.save()
}

func (r *FileRepository) RetireNode(ctx context.Context, tenantID, nodeID string) (domain.Node, error) {
	retired, err := r.Memory.RetireNode(ctx, tenantID, nodeID)
	if err != nil {
		return domain.Node{}, err
	}
	return retired, r.save()
}

func (r *FileRepository) RecordTelemetry(ctx context.Context, report telemetry.Report) (telemetry.Report, error) {
	created, err := r.Memory.RecordTelemetry(ctx, report)
	if err != nil {
		return telemetry.Report{}, err
	}
	return created, r.save()
}

func (r *FileRepository) UpsertPolicyRule(ctx context.Context, rule policy.Rule) (policy.Rule, error) {
	created, err := r.Memory.UpsertPolicyRule(ctx, rule)
	if err != nil {
		return policy.Rule{}, err
	}
	return created, r.save()
}

func (r *FileRepository) UpsertConfig(ctx context.Context, bundle domain.ConfigBundle) (domain.ConfigBundle, error) {
	created, err := r.Memory.UpsertConfig(ctx, bundle)
	if err != nil {
		return domain.ConfigBundle{}, err
	}
	return created, r.save()
}

func (r *FileRepository) RecordAuditEvent(ctx context.Context, event domain.AuditEvent) (domain.AuditEvent, error) {
	created, err := r.Memory.RecordAuditEvent(ctx, event)
	if err != nil {
		return domain.AuditEvent{}, err
	}
	return created, r.save()
}

func (r *FileRepository) save() error {
	return saveSnapshot(r.path, r.Memory.Snapshot())
}

func saveSnapshot(path string, snapshot Snapshot) error {
	return writePrivateJSON(path, snapshot)
}

func writePrivateJSON(path string, value interface{}) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create store directory: %w", err)
	}
	if dir != "." {
		if err := os.Chmod(dir, 0700); err != nil {
			return fmt.Errorf("chmod store directory: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".store-*.tmp")
	if err != nil {
		return fmt.Errorf("create store temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode store json: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close store temp file: %w", err)
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		return fmt.Errorf("chmod store temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace store snapshot: %w", err)
	}
	return nil
}

func loadSnapshot(path string) (Snapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		return Snapshot{}, err
	}
	defer file.Close()
	var snapshot Snapshot
	if err := json.NewDecoder(file).Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode store snapshot: %w", err)
	}
	return snapshot, nil
}

var _ Repository = (*FileRepository)(nil)
