package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"anixops-sd-wan/internal/buildinfo"
	"anixops-sd-wan/internal/release"
	"anixops-sd-wan/internal/system"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: anix-release <manifest|verify|rollback-plan|rollback-run>")
		return 2
	}
	switch args[0] {
	case "--version", "version":
		info := buildinfo.Current("anix-release")
		fmt.Fprintf(stdout, "%s %s %s %s\n", info.Name, info.Version, info.Commit, info.Date)
		return 0
	case "manifest":
		return runManifest(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "rollback-plan":
		return runRollbackPlan(args[1:], stdout, stderr)
	case "rollback-run":
		return runRollbackRun(args[1:], stdout, stderr, system.ExecRunner{})
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		return 2
	}
}

type rollbackRunOutput struct {
	DryRun   bool                    `json:"dry_run"`
	Rollback release.RollbackPlan    `json:"rollback"`
	Result   *release.RollbackResult `json:"result,omitempty"`
}

func runManifest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("manifest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	baseDir := fs.String("base-dir", ".", "directory containing release artifacts")
	output := fs.String("output", "", "write manifest JSON to file instead of stdout")
	product := fs.String("product", "anixops-sd-wan", "product name")
	version := fs.String("release-version", "", "release version")
	commit := fs.String("commit", "", "release commit")
	buildDateRaw := fs.String("build-date", "", "release build date in RFC3339")
	createdAtRaw := fs.String("generated-at", "", "manifest generation time in RFC3339")
	changeID := fs.String("change-id", "", "change ticket or record id")
	previousVersion := fs.String("previous-version", "", "previous release version for rollback")
	impact := multiStringFlag{}
	changeVerification := multiStringFlag{}
	restoreState := multiStringFlag{}
	rollbackCommand := multiStringFlag{}
	verification := multiStringFlag{}
	artifacts := multiStringFlag{}
	fs.Var(&impact, "impact", "release impact scope")
	fs.Var(&changeVerification, "change-verification", "release validation result or command")
	fs.Var(&restoreState, "restore-state", "state path to preserve or restore during rollback")
	fs.Var(&rollbackCommand, "rollback-command", "rollback command written as a space-separated command line")
	fs.Var(&verification, "verification", "rollback verification step")
	fs.Var(&artifacts, "artifact", "artifact path relative to base dir")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	buildDate, err := parseTime(*buildDateRaw)
	if err != nil {
		fmt.Fprintf(stderr, "parse build date: %v\n", err)
		return 2
	}
	createdAt, err := parseTime(*createdAtRaw)
	if err != nil {
		fmt.Fprintf(stderr, "parse generated-at: %v\n", err)
		return 2
	}
	manifest, err := release.BuildManifest(*baseDir, artifacts.Values(), release.ManifestOptions{
		Product:        *product,
		ReleaseVersion: *version,
		Commit:         *commit,
		BuildDate:      buildDate,
		GeneratedAt:    createdAt,
		Change: release.ChangeRecord{
			ID:           *changeID,
			Impact:       impact.Values(),
			Verification: changeVerification.Values(),
		},
		Rollback: release.RollbackPlan{
			PreviousVersion: *previousVersion,
			RestoreState:    restoreState.Values(),
			Commands:        parseCommands(rollbackCommand.Values()),
			Verification:    verification.Values(),
		},
	})
	if err != nil {
		fmt.Fprintf(stderr, "build release manifest: %v\n", err)
		return 1
	}
	if *output != "" {
		if err := release.SaveManifest(*output, manifest); err != nil {
			fmt.Fprintf(stderr, "save release manifest: %v\n", err)
			return 1
		}
		return 0
	}
	encode(stdout, manifest)
	return 0
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	baseDir := fs.String("base-dir", ".", "directory containing release artifacts")
	manifestPath := fs.String("manifest", "", "release manifest JSON file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*manifestPath) == "" {
		fmt.Fprintln(stderr, "--manifest is required")
		return 2
	}
	manifest, err := release.LoadManifest(*manifestPath)
	if err != nil {
		fmt.Fprintf(stderr, "load release manifest: %v\n", err)
		return 1
	}
	if err := release.VerifyManifest(*baseDir, manifest); err != nil {
		fmt.Fprintf(stderr, "verify release manifest: %v\n", err)
		return 1
	}
	encode(stdout, manifest)
	return 0
}

func runRollbackPlan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rollback-plan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifestPath := fs.String("manifest", "", "release manifest JSON file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*manifestPath) == "" {
		fmt.Fprintln(stderr, "--manifest is required")
		return 2
	}
	manifest, err := release.LoadManifest(*manifestPath)
	if err != nil {
		fmt.Fprintf(stderr, "load release manifest: %v\n", err)
		return 1
	}
	encode(stdout, manifest.Rollback)
	return 0
}

func runRollbackRun(args []string, stdout, stderr io.Writer, runner system.Runner) int {
	fs := flag.NewFlagSet("rollback-run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifestPath := fs.String("manifest", "", "release manifest JSON file")
	confirm := fs.Bool("confirm", false, "execute rollback commands; omitted means dry-run")
	timeout := fs.Duration("timeout", 30*time.Second, "rollback execution timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*manifestPath) == "" {
		fmt.Fprintln(stderr, "--manifest is required")
		return 2
	}
	manifest, err := release.LoadManifest(*manifestPath)
	if err != nil {
		fmt.Fprintf(stderr, "load release manifest: %v\n", err)
		return 1
	}
	if !*confirm {
		encode(stdout, rollbackRunOutput{DryRun: true, Rollback: manifest.Rollback})
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := release.ExecuteRollback(ctx, manifest.Rollback, runner)
	if err != nil {
		fmt.Fprintf(stderr, "execute rollback: %v\n", err)
		return 1
	}
	encode(stdout, rollbackRunOutput{DryRun: false, Rollback: manifest.Rollback, Result: &result})
	return 0
}

func encode(w io.Writer, value interface{}) {
	if err := json.NewEncoder(w).Encode(value); err != nil {
		fmt.Fprintf(os.Stderr, "encode output: %v\n", err)
		os.Exit(1)
	}
}

func parseTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, raw)
}

type multiStringFlag struct {
	values []string
}

func (m *multiStringFlag) String() string {
	return strings.Join(m.values, ",")
}

func (m *multiStringFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	m.values = append(m.values, value)
	return nil
}

func (m *multiStringFlag) Values() []string {
	out := make([]string, len(m.values))
	copy(out, m.values)
	return out
}

func parseCommands(raw []string) []release.Command {
	commands := make([]release.Command, 0, len(raw))
	for _, line := range raw {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		command := release.Command{Name: fields[0]}
		if len(fields) > 1 {
			command.Args = append(command.Args, fields[1:]...)
		}
		commands = append(commands, command)
	}
	return commands
}
