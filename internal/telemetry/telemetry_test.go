package telemetry

import "testing"

func TestSanitizedRedactsSensitiveFields(t *testing.T) {
	report := Report{
		TenantID:    "tenant-a",
		SubjectID:   "agent-a",
		SubjectKind: SubjectAgent,
		Logs: []LogRecord{{
			Level:   "info",
			Message: "connected",
			Fields: map[string]string{
				"token":       "secret-token",
				"public_addr": "198.51.100.1",
			},
		}},
	}

	clean := report.Sanitized()
	if clean.Logs[0].Fields["token"] != "[redacted]" {
		t.Fatalf("expected token to be redacted, got %q", clean.Logs[0].Fields["token"])
	}
	if clean.Logs[0].Fields["public_addr"] != "198.51.100.1" {
		t.Fatalf("expected non-sensitive field to remain")
	}
}

func TestReportValidationRejectsNegativeMetrics(t *testing.T) {
	report := Report{
		TenantID:    "tenant-a",
		SubjectID:   "agent-a",
		SubjectKind: SubjectAgent,
		Metrics: map[string]float64{
			"packet_loss": -1,
		},
	}

	if err := report.Validate(); err == nil {
		t.Fatal("expected negative metric to fail validation")
	}
}
