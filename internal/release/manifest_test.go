package release

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildManifestAndVerify(t *testing.T) {
	baseDir := t.TempDir()
	writeArtifact(t, baseDir, "bin/anix-agent", "agent-binary")
	writeArtifact(t, baseDir, "bin/anix-control", "control-binary")

	manifest, err := BuildManifest(baseDir, []string{"bin/anix-agent", "bin/anix-control"}, ManifestOptions{
		Product:        "anixops-sd-wan",
		ReleaseVersion: "v1.2.3",
		Commit:         "abc123",
		BuildDate:      time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC),
		GeneratedAt:    time.Date(2026, 5, 12, 13, 0, 0, 0, time.UTC),
		Change:         testChangeRecord(),
		Rollback: RollbackPlan{
			PreviousVersion: "v1.2.2",
			RestoreState:    []string{"/var/lib/anixops"},
			Commands: []Command{
				{Name: "systemctl", Args: []string{"restart", "anix-control"}},
				{Name: "systemctl", Args: []string{"restart", "anix-agent"}},
			},
			Verification: []string{"anix-control --version", "anix-agent --version"},
		},
	})
	if err != nil {
		t.Fatalf("build manifest: %v", err)
	}
	if manifest.Version != ManifestVersion || manifest.ReleaseVersion != "v1.2.3" {
		t.Fatalf("unexpected manifest metadata: %+v", manifest)
	}
	if len(manifest.Artifacts) != 2 {
		t.Fatalf("expected two artifacts, got %+v", manifest.Artifacts)
	}
	if err := VerifyManifest(baseDir, manifest); err != nil {
		t.Fatalf("verify manifest: %v", err)
	}
}

func TestVerifyManifestRejectsTamperedArtifact(t *testing.T) {
	baseDir := t.TempDir()
	writeArtifact(t, baseDir, "anix-control", "control-binary")

	manifest, err := BuildManifest(baseDir, []string{"anix-control"}, ManifestOptions{
		Product:        "anixops-sd-wan",
		ReleaseVersion: "v1.2.3",
		Commit:         "abc123",
		BuildDate:      time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC),
		GeneratedAt:    time.Date(2026, 5, 12, 13, 0, 0, 0, time.UTC),
		Change:         testChangeRecord(),
		Rollback: RollbackPlan{
			PreviousVersion: "v1.2.2",
			RestoreState:    []string{"/var/lib/anixops"},
			Commands:        []Command{{Name: "systemctl", Args: []string{"restart", "anix-control"}}},
			Verification:    []string{"anix-control --version"},
		},
	})
	if err != nil {
		t.Fatalf("build manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, "anix-control"), []byte("tampered"), 0o644); err != nil {
		t.Fatalf("tamper artifact: %v", err)
	}
	if err := VerifyManifest(baseDir, manifest); err == nil {
		t.Fatal("expected tampered artifact to be rejected")
	}
}

func TestBuildManifestRejectsPathTraversal(t *testing.T) {
	baseDir := t.TempDir()
	writeArtifact(t, baseDir, "artifact", "data")

	_, err := BuildManifest(baseDir, []string{"../escape"}, ManifestOptions{
		Product:        "anixops-sd-wan",
		ReleaseVersion: "v1.2.3",
		Commit:         "abc123",
		BuildDate:      time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC),
		GeneratedAt:    time.Date(2026, 5, 12, 13, 0, 0, 0, time.UTC),
		Change:         testChangeRecord(),
		Rollback: RollbackPlan{
			PreviousVersion: "v1.2.2",
			RestoreState:    []string{"/var/lib/anixops"},
			Commands:        []Command{{Name: "systemctl", Args: []string{"restart", "anix-control"}}},
			Verification:    []string{"anix-control --version"},
		},
	})
	if err == nil {
		t.Fatal("expected path traversal to be rejected")
	}
}

func TestManifestValidateRequiresRollbackPlan(t *testing.T) {
	manifest := Manifest{
		Version:        ManifestVersion,
		Product:        "anixops-sd-wan",
		ReleaseVersion: "v1.2.3",
		Commit:         "abc123",
		BuildDate:      time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC),
		GeneratedAt:    time.Date(2026, 5, 12, 13, 0, 0, 0, time.UTC),
		Change:         testChangeRecord(),
		Artifacts: []Artifact{{
			Path:   "bin/anix-agent",
			Size:   12,
			SHA256: strings.Repeat("a", 64),
		}},
	}
	if err := manifest.Validate(); err == nil {
		t.Fatal("expected missing rollback plan to be rejected")
	}
}

func TestManifestValidateRequiresChangeRecord(t *testing.T) {
	manifest := Manifest{
		Version:        ManifestVersion,
		Product:        "anixops-sd-wan",
		ReleaseVersion: "v1.2.3",
		Commit:         "abc123",
		BuildDate:      time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC),
		GeneratedAt:    time.Date(2026, 5, 12, 13, 0, 0, 0, time.UTC),
		Artifacts: []Artifact{{
			Path:   "bin/anix-agent",
			Size:   12,
			SHA256: strings.Repeat("a", 64),
		}},
		Rollback: RollbackPlan{
			PreviousVersion: "v1.2.2",
			RestoreState:    []string{"/var/lib/anixops"},
			Commands:        []Command{{Name: "systemctl", Args: []string{"restart", "anix-control"}}},
			Verification:    []string{"anix-control --version"},
		},
	}
	if err := manifest.Validate(); err == nil {
		t.Fatal("expected missing change record to be rejected")
	}
}

func TestSaveAndLoadManifest(t *testing.T) {
	baseDir := t.TempDir()
	writeArtifact(t, baseDir, "bin/anix-agent", "agent-binary")

	manifest, err := BuildManifest(baseDir, []string{"bin/anix-agent"}, ManifestOptions{
		Product:        "anixops-sd-wan",
		ReleaseVersion: "v1.2.3",
		Commit:         "abc123",
		BuildDate:      time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC),
		GeneratedAt:    time.Date(2026, 5, 12, 13, 0, 0, 0, time.UTC),
		Change:         testChangeRecord(),
		Rollback: RollbackPlan{
			PreviousVersion: "v1.2.2",
			RestoreState:    []string{"/var/lib/anixops"},
			Commands:        []Command{{Name: "systemctl", Args: []string{"restart", "anix-control"}}},
			Verification:    []string{"anix-control --version"},
		},
	})
	if err != nil {
		t.Fatalf("build manifest: %v", err)
	}
	path := filepath.Join(t.TempDir(), "release.json")
	if err := SaveManifest(path, manifest); err != nil {
		t.Fatalf("save manifest: %v", err)
	}
	loaded, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if err := VerifyManifest(baseDir, loaded); err != nil {
		t.Fatalf("verify loaded manifest: %v", err)
	}
}

func TestManifestJSONShape(t *testing.T) {
	manifest := Manifest{
		Version:        ManifestVersion,
		Product:        "anixops-sd-wan",
		ReleaseVersion: "v1.2.3",
		Commit:         "abc123",
		BuildDate:      time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC),
		GeneratedAt:    time.Date(2026, 5, 12, 13, 0, 0, 0, time.UTC),
		Change:         testChangeRecord(),
		Artifacts: []Artifact{{
			Path:   "bin/anix-agent",
			Size:   12,
			SHA256: strings.Repeat("a", 64),
		}},
		Rollback: RollbackPlan{
			PreviousVersion: "v1.2.2",
			RestoreState:    []string{"/var/lib/anixops"},
			Commands:        []Command{{Name: "systemctl", Args: []string{"restart", "anix-control"}}},
			Verification:    []string{"anix-control --version"},
		},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if !json.Valid(data) {
		t.Fatalf("manifest JSON should be valid, got %s", string(data))
	}
}

func testChangeRecord() ChangeRecord {
	return ChangeRecord{
		ID:           "chg-123",
		Impact:       []string{"control plane and agent binaries"},
		Verification: []string{"go test ./...", "scripts/ci-gate.sh"},
	}
}

func writeArtifact(t *testing.T, baseDir, relativePath, contents string) {
	t.Helper()
	fullPath := filepath.Join(baseDir, filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatalf("mkdir artifact dir: %v", err)
	}
	if err := os.WriteFile(fullPath, []byte(contents), 0o644); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
}
