package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

const BackupVersion = 1

type Backup struct {
	Version        int          `json:"version"`
	CreatedAt      time.Time    `json:"created_at"`
	SnapshotSHA256 string       `json:"snapshot_sha256"`
	Counts         BackupCounts `json:"counts"`
	Snapshot       Snapshot     `json:"snapshot"`
}

type BackupCounts struct {
	Tenants   int `json:"tenants"`
	Devices   int `json:"devices"`
	Nodes     int `json:"nodes"`
	Policies  int `json:"policies"`
	Configs   int `json:"configs"`
	Telemetry int `json:"telemetry"`
	Audit     int `json:"audit"`
}

func NewBackup(snapshot Snapshot, createdAt time.Time) (Backup, error) {
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	sum, err := snapshotSHA256(snapshot)
	if err != nil {
		return Backup{}, err
	}
	backup := Backup{
		Version:        BackupVersion,
		CreatedAt:      createdAt.UTC(),
		SnapshotSHA256: sum,
		Counts:         countSnapshot(snapshot),
		Snapshot:       snapshot,
	}
	if err := backup.Validate(); err != nil {
		return Backup{}, err
	}
	return backup, nil
}

func (r *FileRepository) Backup(path string, createdAt time.Time) (Backup, error) {
	if path == "" {
		return Backup{}, fmt.Errorf("backup file path is required")
	}
	backup, err := NewBackup(r.Memory.Snapshot(), createdAt)
	if err != nil {
		return Backup{}, err
	}
	if err := SaveBackup(path, backup); err != nil {
		return Backup{}, err
	}
	return backup, nil
}

func SaveBackup(path string, backup Backup) error {
	if err := backup.Validate(); err != nil {
		return err
	}
	return writePrivateJSON(path, backup)
}

func LoadBackup(path string) (Backup, error) {
	file, err := os.Open(path)
	if err != nil {
		return Backup{}, fmt.Errorf("open store backup: %w", err)
	}
	defer file.Close()
	var backup Backup
	if err := json.NewDecoder(file).Decode(&backup); err != nil {
		return Backup{}, fmt.Errorf("decode store backup: %w", err)
	}
	if err := backup.Validate(); err != nil {
		return Backup{}, err
	}
	return backup, nil
}

func RestoreBackup(path string, backup Backup) error {
	if path == "" {
		return fmt.Errorf("store restore path is required")
	}
	if err := backup.Validate(); err != nil {
		return err
	}
	return saveSnapshot(path, backup.Snapshot)
}

func RestoreBackupFile(storePath, backupPath string) (Backup, error) {
	backup, err := LoadBackup(backupPath)
	if err != nil {
		return Backup{}, err
	}
	if err := RestoreBackup(storePath, backup); err != nil {
		return Backup{}, err
	}
	return backup, nil
}

func (b Backup) Validate() error {
	if b.Version != BackupVersion {
		return fmt.Errorf("unsupported store backup version %d", b.Version)
	}
	if b.CreatedAt.IsZero() {
		return fmt.Errorf("store backup created_at is required")
	}
	if len(b.SnapshotSHA256) != 64 {
		return fmt.Errorf("store backup snapshot sha256 must be 64 hex characters")
	}
	if _, err := hex.DecodeString(b.SnapshotSHA256); err != nil {
		return fmt.Errorf("store backup snapshot sha256 must be hex: %w", err)
	}
	sum, err := snapshotSHA256(b.Snapshot)
	if err != nil {
		return err
	}
	if sum != b.SnapshotSHA256 {
		return fmt.Errorf("store backup snapshot sha256 mismatch")
	}
	if got := countSnapshot(b.Snapshot); got != b.Counts {
		return fmt.Errorf("store backup counts do not match snapshot")
	}
	return nil
}

func snapshotSHA256(snapshot Snapshot) (string, error) {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return "", fmt.Errorf("marshal store snapshot for checksum: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func countSnapshot(snapshot Snapshot) BackupCounts {
	return BackupCounts{
		Tenants:   len(snapshot.Tenants),
		Devices:   countNestedMap(snapshot.Devices),
		Nodes:     countNestedMap(snapshot.Nodes),
		Policies:  countNestedMap(snapshot.Policies),
		Configs:   countNestedMap(snapshot.Configs),
		Telemetry: countNestedSlice(snapshot.Telemetry),
		Audit:     countNestedSlice(snapshot.Audit),
	}
}

func countNestedMap[T any](values map[string]map[string]T) int {
	total := 0
	for _, inner := range values {
		total += len(inner)
	}
	return total
}

func countNestedSlice[T any](values map[string][]T) int {
	total := 0
	for _, inner := range values {
		total += len(inner)
	}
	return total
}
