package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"anixops-sd-wan/internal/telemetry"
)

const DefaultTelemetryQueueMaxReports = 1024

type TelemetryQueue interface {
	Load() ([]telemetry.Report, error)
	Save([]telemetry.Report) error
}

type FileTelemetryQueue struct {
	path       string
	maxReports int
}

type telemetryQueueFile struct {
	Reports []telemetry.Report `json:"reports"`
}

func NewFileTelemetryQueue(path string) (*FileTelemetryQueue, error) {
	return NewBoundedFileTelemetryQueue(path, DefaultTelemetryQueueMaxReports)
}

func NewBoundedFileTelemetryQueue(path string, maxReports int) (*FileTelemetryQueue, error) {
	if path == "" {
		return nil, fmt.Errorf("telemetry queue path is required")
	}
	if maxReports <= 0 {
		return nil, fmt.Errorf("telemetry queue max reports must be positive")
	}
	return &FileTelemetryQueue{path: path, maxReports: maxReports}, nil
}

func (q *FileTelemetryQueue) Load() ([]telemetry.Report, error) {
	file, err := os.Open(q.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open telemetry queue: %w", err)
	}
	defer file.Close()

	var queued telemetryQueueFile
	if err := json.NewDecoder(file).Decode(&queued); err != nil {
		return nil, fmt.Errorf("decode telemetry queue: %w", err)
	}
	reports := make([]telemetry.Report, 0, len(queued.Reports))
	for _, report := range queued.Reports {
		clean := report.Sanitized()
		if err := clean.Validate(); err != nil {
			return nil, fmt.Errorf("validate telemetry queue: %w", err)
		}
		reports = append(reports, clean)
	}
	return reports, nil
}

func (q *FileTelemetryQueue) Save(reports []telemetry.Report) error {
	if len(reports) == 0 {
		if err := os.Remove(q.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove telemetry queue: %w", err)
		}
		return nil
	}

	clean := make([]telemetry.Report, 0, len(reports))
	for _, report := range reports {
		sanitized := report.Sanitized()
		if err := sanitized.Validate(); err != nil {
			return err
		}
		clean = append(clean, sanitized)
	}
	if len(clean) > q.maxReports {
		clean = clean[len(clean)-q.maxReports:]
	}
	dir := filepath.Dir(q.path)
	if err := ensurePrivateStateDir(dir); err != nil {
		return fmt.Errorf("create telemetry queue directory: %w", err)
	}
	tmp, tmpName, err := createPrivateStateTempFile(dir, ".telemetry-queue-*.tmp")
	if err != nil {
		return fmt.Errorf("create telemetry queue temp file: %w", err)
	}
	defer func() { _ = os.Remove(tmpName) }()

	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(telemetryQueueFile{Reports: clean}); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode telemetry queue: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close telemetry queue temp file: %w", err)
	}
	if err := os.Rename(tmpName, q.path); err != nil {
		return fmt.Errorf("replace telemetry queue: %w", err)
	}
	return nil
}
