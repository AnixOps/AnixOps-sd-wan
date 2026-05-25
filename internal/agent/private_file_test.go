package agent

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/telemetry"
)

func TestFileBackedAgentStateUsesPrivatePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not portable on Windows")
	}
	root := t.TempDir()

	configPath := filepath.Join(root, "config", "cache.json")
	configCache, err := NewFileConfigCache(configPath)
	if err != nil {
		t.Fatalf("new config cache: %v", err)
	}
	if err := configCache.Save(domain.ConfigBundle{
		ID:       "cfg-secure",
		TenantID: "tenant-a",
		TargetID: "agent-a",
		Version:  "v1",
	}); err != nil {
		t.Fatalf("save config cache: %v", err)
	}
	assertPrivateAgentStatePath(t, configPath)

	signingKeyPath := filepath.Join(root, "signing", "key.json")
	signingKeyCache, err := NewFileSigningKeyCache(signingKeyPath)
	if err != nil {
		t.Fatalf("new signing key cache: %v", err)
	}
	if err := signingKeyCache.Save(testSigningPublicKey(t)); err != nil {
		t.Fatalf("save signing key cache: %v", err)
	}
	assertPrivateAgentStatePath(t, signingKeyPath)

	crlPath := filepath.Join(root, "crl", "cache.json")
	crlCache, err := NewFileCRLCache(crlPath)
	if err != nil {
		t.Fatalf("new crl cache: %v", err)
	}
	if err := crlCache.Save(testRevocationList(t, "tenant-a")); err != nil {
		t.Fatalf("save crl cache: %v", err)
	}
	assertPrivateAgentStatePath(t, crlPath)

	approvalPath := filepath.Join(root, "approval", "signing-key.json")
	approval, err := NewSigningKeyApproval(testSigningPublicKey(t), "operator-a", time.Date(2026, 5, 12, 3, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("new signing key approval: %v", err)
	}
	if err := SaveSigningKeyApproval(approvalPath, approval); err != nil {
		t.Fatalf("save signing key approval: %v", err)
	}
	assertPrivateAgentStatePath(t, approvalPath)

	queuePath := filepath.Join(root, "telemetry", "queue.json")
	queue, err := NewFileTelemetryQueue(queuePath)
	if err != nil {
		t.Fatalf("new telemetry queue: %v", err)
	}
	if err := queue.Save([]telemetry.Report{queueReport("agent-a")}); err != nil {
		t.Fatalf("save telemetry queue: %v", err)
	}
	assertPrivateAgentStatePath(t, queuePath)
}

func assertPrivateAgentStatePath(t *testing.T, path string) {
	t.Helper()
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat state dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != privateStateDirMode {
		t.Fatalf("expected private state dir mode %o, got %o", privateStateDirMode, got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != privateStateFileMode {
		t.Fatalf("expected private state file mode %o, got %o", privateStateFileMode, got)
	}
}
