package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"anixops-sd-wan/internal/release"
)

func TestRunManifestVerifyAndRollbackPlan(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, filepath.Join(baseDir, "bin", "anix-agent"), "agent")
	manifestPath := filepath.Join(t.TempDir(), "release.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"manifest",
		"--base-dir", baseDir,
		"--output", manifestPath,
		"--release-version", "v1.2.3",
		"--commit", "abc123",
		"--build-date", "2026-05-12T12:00:00Z",
		"--generated-at", "2026-05-12T13:00:00Z",
		"--change-id", "chg-123",
		"--impact", "agent binary",
		"--change-verification", "go test ./...",
		"--previous-version", "v1.2.2",
		"--restore-state", "/var/lib/anixops",
		"--rollback-command", "systemctl restart anix-agent",
		"--verification", "anix-agent --version",
		"--artifact", "bin/anix-agent",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("manifest command failed code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("expected manifest file: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"verify", "--base-dir", baseDir, "--manifest", manifestPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify command failed code=%d stderr=%s", code, stderr.String())
	}
	var manifest release.Manifest
	if err := json.Unmarshal(stdout.Bytes(), &manifest); err != nil {
		t.Fatalf("verify should write manifest JSON: %v\n%s", err, stdout.String())
	}
	if manifest.ReleaseVersion != "v1.2.3" || len(manifest.Artifacts) != 1 {
		t.Fatalf("unexpected verified manifest: %+v", manifest)
	}
	if manifest.Change.ID != "chg-123" || len(manifest.Change.Impact) != 1 || len(manifest.Change.Verification) != 1 {
		t.Fatalf("expected change record to round trip, got %+v", manifest.Change)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"rollback-plan", "--manifest", manifestPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("rollback-plan command failed code=%d stderr=%s", code, stderr.String())
	}
	var plan release.RollbackPlan
	if err := json.Unmarshal(stdout.Bytes(), &plan); err != nil {
		t.Fatalf("rollback-plan should write JSON: %v\n%s", err, stdout.String())
	}
	if plan.PreviousVersion != "v1.2.2" || len(plan.Commands) != 1 {
		t.Fatalf("unexpected rollback plan: %+v", plan)
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"rollback-run", "--manifest", manifestPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("rollback-run dry-run command failed code=%d stderr=%s", code, stderr.String())
	}
	var dryRun rollbackRunOutput
	if err := json.Unmarshal(stdout.Bytes(), &dryRun); err != nil {
		t.Fatalf("rollback-run dry-run should write JSON: %v\n%s", err, stdout.String())
	}
	if !dryRun.DryRun || len(dryRun.Rollback.Commands) != 1 || dryRun.Result != nil {
		t.Fatalf("unexpected dry-run output: %+v", dryRun)
	}

	stdout.Reset()
	stderr.Reset()
	runner := &testRunner{}
	code = runRollbackRun([]string{"--manifest", manifestPath, "--confirm"}, &stdout, &stderr, runner)
	if code != 0 {
		t.Fatalf("rollback-run confirm command failed code=%d stderr=%s", code, stderr.String())
	}
	var confirmed rollbackRunOutput
	if err := json.Unmarshal(stdout.Bytes(), &confirmed); err != nil {
		t.Fatalf("rollback-run confirm should write JSON: %v\n%s", err, stdout.String())
	}
	if confirmed.DryRun || confirmed.Result == nil || len(confirmed.Result.Commands) != 1 {
		t.Fatalf("unexpected confirmed rollback output: %+v", confirmed)
	}
	if len(runner.commands) != 1 || runner.commands[0].Name != "systemctl" {
		t.Fatalf("expected rollback runner command, got %+v", runner.commands)
	}
}

func TestRunVerifyRejectsTamperedArtifact(t *testing.T) {
	baseDir := t.TempDir()
	artifactPath := filepath.Join(baseDir, "anix-control")
	writeTestFile(t, artifactPath, "control")
	manifestPath := filepath.Join(t.TempDir(), "release.json")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"manifest",
		"--base-dir", baseDir,
		"--output", manifestPath,
		"--release-version", "v1.2.3",
		"--commit", "abc123",
		"--impact", "control binary",
		"--change-verification", "go test ./...",
		"--previous-version", "v1.2.2",
		"--restore-state", "/var/lib/anixops",
		"--rollback-command", "systemctl restart anix-control",
		"--verification", "anix-control --version",
		"--artifact", "anix-control",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("manifest command failed code=%d stderr=%s", code, stderr.String())
	}
	writeTestFile(t, artifactPath, "tampered")

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"verify", "--base-dir", baseDir, "--manifest", manifestPath}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected verify command to reject tampered artifact")
	}
	if !strings.Contains(stderr.String(), "sha256 mismatch") && !strings.Contains(stderr.String(), "size mismatch") {
		t.Fatalf("expected integrity error, got %s", stderr.String())
	}
}

func TestRunManifestRequiresRollbackEvidence(t *testing.T) {
	baseDir := t.TempDir()
	writeTestFile(t, filepath.Join(baseDir, "anix-agent"), "agent")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run([]string{
		"manifest",
		"--base-dir", baseDir,
		"--release-version", "v1.2.3",
		"--commit", "abc123",
		"--impact", "agent binary",
		"--change-verification", "go test ./...",
		"--artifact", "anix-agent",
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected manifest command to require rollback evidence")
	}
	if !strings.Contains(stderr.String(), "rollback") {
		t.Fatalf("expected rollback error, got %s", stderr.String())
	}
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

type testRunner struct {
	commands []release.Command
}

func (r *testRunner) Run(ctx context.Context, name string, args ...string) error {
	r.commands = append(r.commands, release.Command{Name: name, Args: append([]string(nil), args...)})
	return nil
}
