package telemetry

import (
	"fmt"
	"strings"
	"time"
)

type SubjectKind string

const (
	SubjectAgent  SubjectKind = "agent"
	SubjectEdge   SubjectKind = "edge"
	SubjectCore   SubjectKind = "core"
	SubjectEgress SubjectKind = "egress"
)

type LogRecord struct {
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
}

type Report struct {
	TenantID    string             `json:"tenant_id"`
	SubjectID   string             `json:"subject_id"`
	SubjectKind SubjectKind        `json:"subject_kind"`
	Timestamp   time.Time          `json:"timestamp"`
	Metrics     map[string]float64 `json:"metrics,omitempty"`
	Logs        []LogRecord        `json:"logs,omitempty"`
}

func (r Report) Validate() error {
	if strings.TrimSpace(r.TenantID) == "" {
		return fmt.Errorf("telemetry tenant id is required")
	}
	if strings.TrimSpace(r.SubjectID) == "" {
		return fmt.Errorf("telemetry subject id is required")
	}
	if r.SubjectKind == "" {
		return fmt.Errorf("telemetry subject kind is required")
	}
	for name, value := range r.Metrics {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("telemetry metric name is required")
		}
		if value < 0 {
			return fmt.Errorf("telemetry metric %q must be non-negative", name)
		}
	}
	return nil
}

func (r Report) Sanitized() Report {
	clean := r
	if clean.Timestamp.IsZero() {
		clean.Timestamp = time.Now().UTC()
	}
	if clean.Metrics != nil {
		clean.Metrics = make(map[string]float64, len(r.Metrics))
		for key, value := range r.Metrics {
			clean.Metrics[key] = value
		}
	}
	if clean.Logs != nil {
		clean.Logs = make([]LogRecord, 0, len(r.Logs))
		for _, log := range r.Logs {
			clean.Logs = append(clean.Logs, sanitizeLog(log))
		}
	}
	return clean
}

func sanitizeLog(log LogRecord) LogRecord {
	clean := log
	if clean.Fields == nil {
		return clean
	}

	clean.Fields = make(map[string]string, len(log.Fields))
	for key, value := range log.Fields {
		if sensitiveKey(key) {
			clean.Fields[key] = "[redacted]"
			continue
		}
		clean.Fields[key] = value
	}
	return clean
}

func sensitiveKey(key string) bool {
	k := strings.ToLower(key)
	return strings.Contains(k, "password") ||
		strings.Contains(k, "token") ||
		strings.Contains(k, "secret") ||
		strings.Contains(k, "private_key") ||
		strings.Contains(k, "credential")
}
