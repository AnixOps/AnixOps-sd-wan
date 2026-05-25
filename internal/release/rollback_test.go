package release

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestExecuteRollbackRunsStructuredCommands(t *testing.T) {
	runner := &recordingRunner{}
	plan := testRollbackPlan()

	result, err := ExecuteRollback(context.Background(), plan, runner)
	if err != nil {
		t.Fatalf("execute rollback: %v", err)
	}
	if result.PreviousVersion != "v1.2.2" || len(result.Commands) != 2 {
		t.Fatalf("unexpected rollback result: %+v", result)
	}
	if len(runner.commands) != 2 || runner.commands[0].Name != "systemctl" || strings.Join(runner.commands[0].Args, " ") != "restart anix-control" {
		t.Fatalf("unexpected runner commands: %+v", runner.commands)
	}
}

func TestExecuteRollbackStopsOnCommandError(t *testing.T) {
	runner := &recordingRunner{errAt: 1, err: errors.New("restart failed")}
	plan := testRollbackPlan()

	result, err := ExecuteRollback(context.Background(), plan, runner)
	if err == nil {
		t.Fatal("expected rollback command error")
	}
	if len(result.Commands) != 1 {
		t.Fatalf("expected only successful command in result, got %+v", result)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("expected runner to stop after failing second command, got %+v", runner.commands)
	}
}

func TestExecuteRollbackRejectsInvalidPlan(t *testing.T) {
	if _, err := ExecuteRollback(context.Background(), RollbackPlan{}, &recordingRunner{}); err == nil {
		t.Fatal("expected invalid rollback plan to be rejected")
	}
}

func testRollbackPlan() RollbackPlan {
	return RollbackPlan{
		PreviousVersion: "v1.2.2",
		RestoreState:    []string{"/var/lib/anixops"},
		Commands: []Command{
			{Name: "systemctl", Args: []string{"restart", "anix-control"}},
			{Name: "systemctl", Args: []string{"restart", "anix-agent"}},
		},
		Verification: []string{"anix-control --version", "anix-agent --version"},
	}
}

type recordingRunner struct {
	commands []Command
	errAt    int
	err      error
}

func (r *recordingRunner) Run(ctx context.Context, name string, args ...string) error {
	r.commands = append(r.commands, Command{Name: name, Args: append([]string(nil), args...)})
	if r.err != nil && len(r.commands)-1 == r.errAt {
		return r.err
	}
	return nil
}
