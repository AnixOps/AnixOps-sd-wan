package release

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const ManifestVersion = 1

type Manifest struct {
	Version        int          `json:"version"`
	Product        string       `json:"product"`
	ReleaseVersion string       `json:"release_version"`
	Commit         string       `json:"commit"`
	BuildDate      time.Time    `json:"build_date"`
	GeneratedAt    time.Time    `json:"generated_at"`
	Change         ChangeRecord `json:"change"`
	Artifacts      []Artifact   `json:"artifacts"`
	Rollback       RollbackPlan `json:"rollback"`
}

type Artifact struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type RollbackPlan struct {
	PreviousVersion string    `json:"previous_version"`
	RestoreState    []string  `json:"restore_state,omitempty"`
	Commands        []Command `json:"commands,omitempty"`
	Verification    []string  `json:"verification,omitempty"`
}

type Command struct {
	Name string   `json:"name"`
	Args []string `json:"args,omitempty"`
}

type ChangeRecord struct {
	ID           string   `json:"id,omitempty"`
	Impact       []string `json:"impact"`
	Verification []string `json:"verification"`
}

type ManifestOptions struct {
	Product        string
	ReleaseVersion string
	Commit         string
	BuildDate      time.Time
	GeneratedAt    time.Time
	Change         ChangeRecord
	Rollback       RollbackPlan
}

func BuildManifest(baseDir string, artifactPaths []string, opts ManifestOptions) (Manifest, error) {
	if opts.GeneratedAt.IsZero() {
		opts.GeneratedAt = time.Now().UTC()
	}
	if opts.BuildDate.IsZero() {
		opts.BuildDate = opts.GeneratedAt
	}
	manifest := Manifest{
		Version:        ManifestVersion,
		Product:        strings.TrimSpace(opts.Product),
		ReleaseVersion: strings.TrimSpace(opts.ReleaseVersion),
		Commit:         strings.TrimSpace(opts.Commit),
		BuildDate:      opts.BuildDate.UTC(),
		GeneratedAt:    opts.GeneratedAt.UTC(),
		Change:         normalizeChangeRecord(opts.Change),
		Rollback:       normalizeRollbackPlan(opts.Rollback),
	}
	base, err := filepath.Abs(baseDir)
	if err != nil {
		return Manifest{}, fmt.Errorf("resolve release base dir: %w", err)
	}
	seen := map[string]struct{}{}
	for _, rawPath := range artifactPaths {
		path, err := normalizeArtifactPath(base, rawPath)
		if err != nil {
			return Manifest{}, err
		}
		if _, ok := seen[path]; ok {
			return Manifest{}, fmt.Errorf("duplicate release artifact %q", path)
		}
		seen[path] = struct{}{}
		artifact, err := scanArtifact(base, path)
		if err != nil {
			return Manifest{}, err
		}
		manifest.Artifacts = append(manifest.Artifacts, artifact)
	}
	sort.Slice(manifest.Artifacts, func(i, j int) bool {
		return manifest.Artifacts[i].Path < manifest.Artifacts[j].Path
	})
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func VerifyManifest(baseDir string, manifest Manifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	base, err := filepath.Abs(baseDir)
	if err != nil {
		return fmt.Errorf("resolve release base dir: %w", err)
	}
	for _, expected := range manifest.Artifacts {
		actual, err := scanArtifact(base, expected.Path)
		if err != nil {
			return err
		}
		if actual.Size != expected.Size {
			return fmt.Errorf("release artifact %q size mismatch: manifest=%d actual=%d", expected.Path, expected.Size, actual.Size)
		}
		if actual.SHA256 != expected.SHA256 {
			return fmt.Errorf("release artifact %q sha256 mismatch", expected.Path)
		}
	}
	return nil
}

func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read release manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode release manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func SaveManifest(path string, manifest Manifest) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode release manifest: %w", err)
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create release manifest directory: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write release manifest: %w", err)
	}
	return nil
}

func (m Manifest) Validate() error {
	if m.Version != ManifestVersion {
		return fmt.Errorf("unsupported release manifest version %d", m.Version)
	}
	if strings.TrimSpace(m.Product) == "" {
		return fmt.Errorf("release product is required")
	}
	if strings.TrimSpace(m.ReleaseVersion) == "" {
		return fmt.Errorf("release version is required")
	}
	if strings.TrimSpace(m.Commit) == "" {
		return fmt.Errorf("release commit is required")
	}
	if m.BuildDate.IsZero() {
		return fmt.Errorf("release build date is required")
	}
	if m.GeneratedAt.IsZero() {
		return fmt.Errorf("release generated_at is required")
	}
	if len(m.Artifacts) == 0 {
		return fmt.Errorf("release manifest must contain at least one artifact")
	}
	if err := m.Change.Validate(); err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for _, artifact := range m.Artifacts {
		if err := artifact.Validate(); err != nil {
			return err
		}
		if _, ok := seen[artifact.Path]; ok {
			return fmt.Errorf("duplicate release artifact %q", artifact.Path)
		}
		seen[artifact.Path] = struct{}{}
	}
	if err := m.Rollback.Validate(); err != nil {
		return err
	}
	return nil
}

func (a Artifact) Validate() error {
	path, err := cleanRelativeArtifactPath(a.Path)
	if err != nil {
		return err
	}
	if path != a.Path {
		return fmt.Errorf("release artifact path %q is not normalized", a.Path)
	}
	if a.Size < 0 {
		return fmt.Errorf("release artifact %q size cannot be negative", a.Path)
	}
	if len(a.SHA256) != 64 {
		return fmt.Errorf("release artifact %q sha256 must be 64 hex characters", a.Path)
	}
	if _, err := hex.DecodeString(a.SHA256); err != nil {
		return fmt.Errorf("release artifact %q sha256 must be hex: %w", a.Path, err)
	}
	return nil
}

func (c ChangeRecord) Validate() error {
	if len(c.Impact) == 0 {
		return fmt.Errorf("release change impact is required")
	}
	if len(c.Verification) == 0 {
		return fmt.Errorf("release change verification is required")
	}
	for _, impact := range c.Impact {
		if strings.TrimSpace(impact) == "" {
			return fmt.Errorf("release change impact item is required")
		}
	}
	for _, verification := range c.Verification {
		if strings.TrimSpace(verification) == "" {
			return fmt.Errorf("release change verification item is required")
		}
	}
	return nil
}

func (p RollbackPlan) Validate() error {
	if strings.TrimSpace(p.PreviousVersion) == "" {
		return fmt.Errorf("release rollback previous version is required")
	}
	if len(p.RestoreState) == 0 {
		return fmt.Errorf("release rollback restore state paths are required")
	}
	if len(p.Commands) == 0 {
		return fmt.Errorf("release rollback commands are required")
	}
	if len(p.Verification) == 0 {
		return fmt.Errorf("release rollback verification steps are required")
	}
	for _, path := range p.RestoreState {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("release rollback restore state path is required")
		}
	}
	for _, command := range p.Commands {
		if err := command.Validate(); err != nil {
			return err
		}
	}
	for _, step := range p.Verification {
		if strings.TrimSpace(step) == "" {
			return fmt.Errorf("release rollback verification step is required")
		}
	}
	return nil
}

func (c Command) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("release rollback command name is required")
	}
	if strings.ContainsAny(c.Name, "\x00\r\n") {
		return fmt.Errorf("release rollback command name contains unsafe characters")
	}
	for _, arg := range c.Args {
		if strings.ContainsAny(arg, "\x00\r\n") {
			return fmt.Errorf("release rollback command argument contains unsafe characters")
		}
	}
	return nil
}

func normalizeChangeRecord(change ChangeRecord) ChangeRecord {
	change.ID = strings.TrimSpace(change.ID)
	change.Impact = trimNonEmpty(change.Impact)
	change.Verification = trimNonEmpty(change.Verification)
	return change
}

func normalizeRollbackPlan(plan RollbackPlan) RollbackPlan {
	plan.PreviousVersion = strings.TrimSpace(plan.PreviousVersion)
	plan.RestoreState = trimNonEmpty(plan.RestoreState)
	plan.Verification = trimNonEmpty(plan.Verification)
	commands := make([]Command, 0, len(plan.Commands))
	for _, command := range plan.Commands {
		command.Name = strings.TrimSpace(command.Name)
		args := make([]string, 0, len(command.Args))
		for _, arg := range command.Args {
			arg = strings.TrimSpace(arg)
			if arg != "" {
				args = append(args, arg)
			}
		}
		command.Args = args
		commands = append(commands, command)
	}
	plan.Commands = commands
	return plan
}

func trimNonEmpty(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func normalizeArtifactPath(baseDir, rawPath string) (string, error) {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" {
		return "", fmt.Errorf("release artifact path is required")
	}
	if filepath.IsAbs(rawPath) {
		rel, err := filepath.Rel(baseDir, rawPath)
		if err != nil {
			return "", fmt.Errorf("resolve release artifact %q: %w", rawPath, err)
		}
		rawPath = rel
	}
	return cleanRelativeArtifactPath(filepath.ToSlash(rawPath))
}

func cleanRelativeArtifactPath(rawPath string) (string, error) {
	normalizedInput := strings.ReplaceAll(strings.TrimSpace(rawPath), "\\", "/")
	path := filepath.ToSlash(filepath.Clean(normalizedInput))
	if path == "." || path == "" {
		return "", fmt.Errorf("release artifact path is required")
	}
	if strings.HasPrefix(path, "/") || path == ".." || strings.HasPrefix(path, "../") || strings.Contains(path, "/../") {
		return "", fmt.Errorf("release artifact path %q must stay inside the release directory", rawPath)
	}
	if strings.ContainsAny(path, "\x00\r\n") {
		return "", fmt.Errorf("release artifact path %q contains unsafe characters", rawPath)
	}
	return path, nil
}

func scanArtifact(baseDir, path string) (Artifact, error) {
	cleanPath, err := cleanRelativeArtifactPath(path)
	if err != nil {
		return Artifact{}, err
	}
	fullPath := filepath.Join(baseDir, filepath.FromSlash(cleanPath))
	info, err := os.Stat(fullPath)
	if err != nil {
		return Artifact{}, fmt.Errorf("stat release artifact %q: %w", cleanPath, err)
	}
	if info.IsDir() {
		return Artifact{}, fmt.Errorf("release artifact %q is a directory", cleanPath)
	}
	file, err := os.Open(fullPath)
	if err != nil {
		return Artifact{}, fmt.Errorf("open release artifact %q: %w", cleanPath, err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return Artifact{}, fmt.Errorf("hash release artifact %q: %w", cleanPath, err)
	}
	return Artifact{
		Path:   cleanPath,
		Size:   info.Size(),
		SHA256: hex.EncodeToString(hash.Sum(nil)),
	}, nil
}
