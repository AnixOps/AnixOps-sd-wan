package protocolinterop

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"

	"anixops-sd-wan/internal/transport"
)

type BinaryRequirement struct {
	Protocol transport.Protocol `json:"protocol"`
	Binary   string             `json:"binary"`
	Reason   string             `json:"reason"`
}

type BinaryStatus struct {
	Requirement BinaryRequirement `json:"requirement"`
	Path        string            `json:"path,omitempty"`
	Available   bool              `json:"available"`
}

type Command struct {
	Name string   `json:"name"`
	Args []string `json:"args"`
}

type Plan struct {
	Statuses []BinaryStatus `json:"statuses"`
	Commands []Command      `json:"commands"`
	Blocked  bool           `json:"blocked"`
}

type LookPath func(file string) (string, error)
type CommandRunner func(ctx context.Context, name string, args ...string) (string, error)

type CommandStatus struct {
	Requirement BinaryRequirement `json:"requirement"`
	Path        string            `json:"path,omitempty"`
	Available   bool              `json:"available"`
	Command     Command           `json:"command,omitempty"`
	Runnable    bool              `json:"runnable"`
	Output      string            `json:"output,omitempty"`
	Error       string            `json:"error,omitempty"`
}

type Report struct {
	Statuses []CommandStatus `json:"statuses"`
	Commands []Command       `json:"commands"`
	Blocked  bool            `json:"blocked"`
}

func Requirements() []BinaryRequirement {
	return []BinaryRequirement{
		{
			Protocol: transport.ProtocolWireGuard,
			Binary:   "wg",
			Reason:   "validate and inspect WireGuard overlay state",
		},
		{
			Protocol: transport.ProtocolHysteria2,
			Binary:   "hysteria",
			Reason:   "validate Hysteria2 client/server availability",
		},
		{
			Protocol: transport.ProtocolReality,
			Binary:   "xray",
			Reason:   "validate REALITY transport via Xray-compatible runtime",
		},
		{
			Protocol: transport.ProtocolTUIC,
			Binary:   "tuic",
			Reason:   "validate TUIC client/server availability",
		},
	}
}

func Probe(lookPath LookPath) ([]BinaryStatus, error) {
	if lookPath == nil {
		return nil, fmt.Errorf("lookPath is required")
	}

	requirements := Requirements()
	statuses := make([]BinaryStatus, 0, len(requirements))
	for _, requirement := range requirements {
		path, err := lookPath(requirement.Binary)
		status := BinaryStatus{Requirement: requirement}
		if err == nil {
			status.Path = path
			status.Available = true
		}
		statuses = append(statuses, status)
	}
	sort.Slice(statuses, func(i, j int) bool {
		return statuses[i].Requirement.Protocol < statuses[j].Requirement.Protocol
	})
	return statuses, nil
}

func BuildPlan(statuses []BinaryStatus) Plan {
	plan := Plan{Statuses: append([]BinaryStatus(nil), statuses...)}
	for _, status := range plan.Statuses {
		if !status.Available {
			plan.Blocked = true
			continue
		}
		plan.Commands = append(plan.Commands, versionCommand(status.Requirement.Binary))
	}
	sort.Slice(plan.Commands, func(i, j int) bool { return plan.Commands[i].Name < plan.Commands[j].Name })
	return plan
}

func RunPreflight(ctx context.Context, lookPath LookPath, runner CommandRunner) (Report, error) {
	if runner == nil {
		return Report{}, fmt.Errorf("command runner is required")
	}
	statuses, err := Probe(lookPath)
	if err != nil {
		return Report{}, err
	}
	plan := BuildPlan(statuses)
	report := Report{
		Commands: append([]Command(nil), plan.Commands...),
		Blocked:  plan.Blocked,
	}
	for _, status := range statuses {
		commandStatus := CommandStatus{
			Requirement: status.Requirement,
			Path:        status.Path,
			Available:   status.Available,
		}
		if !status.Available {
			commandStatus.Error = "binary not found"
			report.Statuses = append(report.Statuses, commandStatus)
			report.Blocked = true
			continue
		}
		command := versionCommand(status.Requirement.Binary)
		commandStatus.Command = command
		output, err := runner(ctx, command.Name, command.Args...)
		commandStatus.Output = trimOutput(output)
		if err != nil {
			commandStatus.Error = err.Error()
			report.Blocked = true
		} else {
			commandStatus.Runnable = true
		}
		report.Statuses = append(report.Statuses, commandStatus)
	}
	return report, nil
}

func ExecCommandRunner(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func ExecCommandRunnerLookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func versionCommand(binary string) Command {
	switch binary {
	case "wg":
		return Command{Name: "wg", Args: []string{"--version"}}
	case "hysteria":
		return Command{Name: "hysteria", Args: []string{"version"}}
	case "xray":
		return Command{Name: "xray", Args: []string{"version"}}
	case "tuic":
		return Command{Name: "tuic", Args: []string{"-v"}}
	default:
		return Command{Name: binary, Args: []string{"--version"}}
	}
}

func trimOutput(output string) string {
	output = strings.TrimSpace(output)
	const limit = 4096
	if len(output) <= limit {
		return output
	}
	return output[:limit] + "...[truncated]"
}
