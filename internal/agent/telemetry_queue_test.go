package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"anixops-sd-wan/internal/telemetry"
)

func TestFileTelemetryQueueSavesLoadsAndClearsReports(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telemetry", "queue.json")
	queue, err := NewFileTelemetryQueue(path)
	if err != nil {
		t.Fatalf("new telemetry queue: %v", err)
	}

	report := telemetry.Report{
		TenantID:    "tenant-a",
		SubjectID:   "agent-a",
		SubjectKind: telemetry.SubjectAgent,
		Timestamp:   time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC),
		Logs: []telemetry.LogRecord{{
			Level:   "info",
			Message: "queued",
			Fields:  map[string]string{"token": "secret-token", "status": "ok"},
		}},
	}
	if err := queue.Save([]telemetry.Report{report}); err != nil {
		t.Fatalf("save queue: %v", err)
	}
	loaded, err := queue.Load()
	if err != nil {
		t.Fatalf("load queue: %v", err)
	}
	if len(loaded) != 1 || loaded[0].TenantID != "tenant-a" {
		t.Fatalf("unexpected loaded reports: %+v", loaded)
	}
	if got := loaded[0].Logs[0].Fields["token"]; got != "[redacted]" {
		t.Fatalf("expected sensitive field to be redacted, got %q", got)
	}

	if err := queue.Save(nil); err != nil {
		t.Fatalf("clear queue: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected queue file to be removed, stat err=%v", err)
	}
}

func TestFileTelemetryQueueKeepsNewestReportsWithinCapacity(t *testing.T) {
	queue, err := NewBoundedFileTelemetryQueue(filepath.Join(t.TempDir(), "telemetry-queue.json"), 2)
	if err != nil {
		t.Fatalf("new telemetry queue: %v", err)
	}
	reports := []telemetry.Report{
		queueReport("first"),
		queueReport("second"),
		queueReport("third"),
	}
	if err := queue.Save(reports); err != nil {
		t.Fatalf("save queue: %v", err)
	}
	loaded, err := queue.Load()
	if err != nil {
		t.Fatalf("load queue: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("expected two reports after capacity trim, got %+v", loaded)
	}
	if loaded[0].SubjectID != "second" || loaded[1].SubjectID != "third" {
		t.Fatalf("expected newest reports to remain, got %+v", loaded)
	}
}

func TestFileTelemetryQueueRejectsInvalidCapacity(t *testing.T) {
	if _, err := NewBoundedFileTelemetryQueue(filepath.Join(t.TempDir(), "telemetry-queue.json"), 0); err == nil {
		t.Fatal("expected invalid capacity to be rejected")
	}
}

func queueReport(subjectID string) telemetry.Report {
	return telemetry.Report{
		TenantID:    "tenant-a",
		SubjectID:   subjectID,
		SubjectKind: telemetry.SubjectAgent,
		Timestamp:   time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC),
	}
}
