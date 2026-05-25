package protocolinterop

import (
	"context"
	"errors"
	"testing"
)

func TestProbeReportsMissingBinaries(t *testing.T) {
	statuses, err := Probe(func(file string) (string, error) {
		return "", errors.New("not found")
	})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if len(statuses) != 4 {
		t.Fatalf("expected four protocol statuses, got %d", len(statuses))
	}
	for _, status := range statuses {
		if status.Available {
			t.Fatalf("expected %s to be unavailable", status.Requirement.Binary)
		}
	}

	plan := BuildPlan(statuses)
	if !plan.Blocked {
		t.Fatal("expected plan to be blocked when binaries are missing")
	}
	if len(plan.Commands) != 0 {
		t.Fatalf("expected no commands for blocked plan, got %+v", plan.Commands)
	}
}

func TestBuildPlanCreatesVersionCommandsForAvailableBinaries(t *testing.T) {
	statuses, err := Probe(func(file string) (string, error) {
		return "/usr/bin/" + file, nil
	})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	plan := BuildPlan(statuses)
	if plan.Blocked {
		t.Fatal("expected complete binary set not to be blocked")
	}
	if len(plan.Commands) != 4 {
		t.Fatalf("expected four commands, got %+v", plan.Commands)
	}
}

func TestRunPreflightRunsVersionCommands(t *testing.T) {
	report, err := RunPreflight(context.Background(), func(file string) (string, error) {
		return "/usr/bin/" + file, nil
	}, func(ctx context.Context, name string, args ...string) (string, error) {
		return name + " ok", nil
	})
	if err != nil {
		t.Fatalf("run preflight: %v", err)
	}
	if report.Blocked {
		t.Fatalf("expected runnable preflight, got %+v", report)
	}
	if len(report.Statuses) != 4 {
		t.Fatalf("expected four statuses, got %+v", report.Statuses)
	}
	for _, status := range report.Statuses {
		if !status.Runnable || status.Output == "" || status.Error != "" {
			t.Fatalf("expected runnable status with output, got %+v", status)
		}
	}
}

func TestRunPreflightBlocksOnCommandError(t *testing.T) {
	report, err := RunPreflight(context.Background(), func(file string) (string, error) {
		return "/usr/bin/" + file, nil
	}, func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "xray" {
			return "broken", errors.New("exit status 1")
		}
		return name + " ok", nil
	})
	if err != nil {
		t.Fatalf("run preflight: %v", err)
	}
	if !report.Blocked {
		t.Fatalf("expected command error to block preflight: %+v", report)
	}
	found := false
	for _, status := range report.Statuses {
		if status.Requirement.Binary == "xray" {
			found = true
			if status.Runnable || status.Error == "" || status.Output != "broken" {
				t.Fatalf("unexpected xray command status: %+v", status)
			}
		}
	}
	if !found {
		t.Fatal("expected xray status")
	}
}

func TestVersionCommandUsesNonPrivilegedWireGuardCheck(t *testing.T) {
	command := versionCommand("wg")
	if len(command.Args) != 1 || command.Args[0] != "--version" {
		t.Fatalf("expected wg --version command, got %+v", command)
	}
}
