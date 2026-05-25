package protocol

import (
	"context"
	"os"
	"testing"

	"anixops-sd-wan/internal/protocolinterop"
)

func TestProtocolInteropPrerequisites(t *testing.T) {
	report, err := protocolinterop.RunPreflight(context.Background(), protocolinterop.ExecCommandRunnerLookPath, protocolinterop.ExecCommandRunner)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if report.Blocked {
		if os.Getenv("ANIXOPS_REQUIRE_PROTOCOL_INTEROP") == "1" {
			t.Fatalf("protocol interop blocked; install runnable wg, hysteria, xray and tuic plus test topology to run real protocol tests: %+v", report.Statuses)
		}
		t.Skipf("protocol interop blocked; install runnable wg, hysteria, xray and tuic plus test topology to run real protocol tests: %+v", report.Statuses)
	}
}
