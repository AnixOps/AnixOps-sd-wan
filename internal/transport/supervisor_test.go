package transport

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSupervisorActivatesCommandLifecycle(t *testing.T) {
	runner := &recordingCommandRunner{}
	supervisor, err := NewSupervisor(nil, runner, []ProtocolLifecycleSpec{{
		Protocol: ProtocolWireGuard,
		Mode:     LifecycleCommand,
		Start:    ProcessCommand{Name: "wg-quick", Args: []string{"up", "wg0.conf"}},
		Stop:     ProcessCommand{Name: "wg-quick", Args: []string{"down", "wg0.conf"}},
	}})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}

	if err := supervisor.Activate(context.Background(), ProtocolWireGuard); err != nil {
		t.Fatalf("activate wireguard: %v", err)
	}
	if len(runner.commands) != 1 || runner.commands[0].String() != "wg-quick up wg0.conf" {
		t.Fatalf("expected wg-quick up command, got %+v", runner.commands)
	}
	if err := supervisor.Activate(context.Background(), ProtocolWireGuard); err != nil {
		t.Fatalf("activate same protocol: %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("expected same protocol activation to be a no-op, got %+v", runner.commands)
	}
	if err := supervisor.Stop(context.Background()); err != nil {
		t.Fatalf("stop wireguard: %v", err)
	}
	if len(runner.commands) != 2 || runner.commands[1].String() != "wg-quick down wg0.conf" {
		t.Fatalf("expected wg-quick down command, got %+v", runner.commands)
	}
	if active, ok := supervisor.Active(); ok || active != "" {
		t.Fatalf("expected no active protocol after stop, got %s ok=%v", active, ok)
	}
}

func TestSupervisorSwitchesProcessLifecycle(t *testing.T) {
	starter := &recordingProcessStarter{}
	supervisor := newProcessSupervisor(t, starter)

	if err := supervisor.Activate(context.Background(), ProtocolHysteria2); err != nil {
		t.Fatalf("activate hysteria2: %v", err)
	}
	firstProcess := starter.processes[0]
	if err := supervisor.Activate(context.Background(), ProtocolReality); err != nil {
		t.Fatalf("activate reality: %v", err)
	}
	if !firstProcess.stopped {
		t.Fatal("expected previous process to be stopped during switch")
	}
	if got := commandStrings(starter.commands); strings.Join(got, "|") != "hysteria client -c h.yaml|xray run -config reality.json" {
		t.Fatalf("unexpected start commands: %+v", got)
	}
	if active, ok := supervisor.Active(); !ok || active != ProtocolReality {
		t.Fatalf("expected active reality, got %s ok=%v", active, ok)
	}
}

func TestSupervisorRestoresPreviousProtocolOnStartFailure(t *testing.T) {
	startErr := errors.New("xray missing")
	starter := &recordingProcessStarter{errors: map[string]error{"xray run -config reality.json": startErr}}
	supervisor := newProcessSupervisor(t, starter)

	if err := supervisor.Activate(context.Background(), ProtocolHysteria2); err != nil {
		t.Fatalf("activate hysteria2: %v", err)
	}
	firstProcess := starter.processes[0]
	err := supervisor.Activate(context.Background(), ProtocolReality)
	if err == nil {
		t.Fatal("expected reality activation to fail")
	}
	if !strings.Contains(err.Error(), startErr.Error()) {
		t.Fatalf("expected start error in message, got %v", err)
	}
	if !firstProcess.stopped {
		t.Fatal("expected failed switch to stop previous process before restore")
	}
	if got := commandStrings(starter.commands); strings.Join(got, "|") != "hysteria client -c h.yaml|xray run -config reality.json|hysteria client -c h.yaml" {
		t.Fatalf("unexpected command sequence: %+v", got)
	}
	if active, ok := supervisor.Active(); !ok || active != ProtocolHysteria2 {
		t.Fatalf("expected restored hysteria2, got %s ok=%v", active, ok)
	}
}

func TestSwitchRuntimeAppliesThroughSupervisor(t *testing.T) {
	runner := &recordingCommandRunner{}
	starter := &recordingProcessStarter{}
	supervisor, err := NewSupervisor(starter, runner, []ProtocolLifecycleSpec{
		{
			Protocol: ProtocolHysteria2,
			Mode:     LifecycleProcess,
			Start:    ProcessCommand{Name: "hysteria", Args: []string{"client", "-c", "h.yaml"}},
		},
		{
			Protocol: ProtocolWireGuard,
			Mode:     LifecycleCommand,
			Start:    ProcessCommand{Name: "wg-quick", Args: []string{"up", "wg0.conf"}},
			Stop:     ProcessCommand{Name: "wg-quick", Args: []string{"down", "wg0.conf"}},
		},
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	if err := supervisor.Activate(context.Background(), ProtocolHysteria2); err != nil {
		t.Fatalf("activate hysteria2: %v", err)
	}
	runtime, err := NewSwitchRuntime(ProtocolHysteria2, 0, nil)
	if err != nil {
		t.Fatalf("new switch runtime: %v", err)
	}

	report, err := runtime.Evaluate(context.Background(), time.Now().UTC(), Signals{
		LinkClass:    LinkDedicated,
		UDPAvailable: true,
	}, supervisor.Activate)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !report.Applied || runtime.Active() != ProtocolWireGuard {
		t.Fatalf("expected runtime to apply wireguard, active=%s report=%+v", runtime.Active(), report)
	}
	if active, ok := supervisor.Active(); !ok || active != ProtocolWireGuard {
		t.Fatalf("expected supervisor active wireguard, got %s ok=%v", active, ok)
	}
	if len(starter.processes) != 1 || !starter.processes[0].stopped {
		t.Fatalf("expected previous process stopped, got %+v", starter.processes)
	}
	if len(runner.commands) != 1 || runner.commands[0].String() != "wg-quick up wg0.conf" {
		t.Fatalf("expected wireguard start command, got %+v", runner.commands)
	}
}

func TestDefaultLifecycleSpecsCoverKnownProtocols(t *testing.T) {
	specs := DefaultLifecycleSpecs("/tmp/anixops")
	seen := make(map[Protocol]bool)
	for _, spec := range specs {
		if err := spec.Validate(); err != nil {
			t.Fatalf("default spec should validate: %v", err)
		}
		seen[spec.Protocol] = true
	}
	for _, protocol := range []Protocol{ProtocolWireGuard, ProtocolHysteria2, ProtocolReality, ProtocolTUIC} {
		if !seen[protocol] {
			t.Fatalf("expected default lifecycle spec for %s", protocol)
		}
	}
}

func TestDefaultServerLifecycleSpecsCoverIngressProtocols(t *testing.T) {
	specs := DefaultServerLifecycleSpecs("/tmp/anixops")
	want := map[Protocol]string{
		ProtocolHysteria2: "hysteria server -c /tmp/anixops/hysteria2.yaml",
		ProtocolReality:   "xray run -config /tmp/anixops/reality.json",
		ProtocolTUIC:      "tuic-server -c /tmp/anixops/tuic.json",
	}
	if len(specs) != len(want) {
		t.Fatalf("expected %d server lifecycle specs, got %+v", len(want), specs)
	}
	for _, spec := range specs {
		if err := spec.Validate(); err != nil {
			t.Fatalf("default server spec should validate: %v", err)
		}
		if spec.Mode != LifecycleProcess {
			t.Fatalf("expected server spec to use process lifecycle, got %+v", spec)
		}
		command := recordingCommand{name: spec.Start.Name, args: spec.Start.Args}.String()
		if command != want[spec.Protocol] {
			t.Fatalf("unexpected server lifecycle command for %s: %s", spec.Protocol, command)
		}
		delete(want, spec.Protocol)
	}
	for protocol := range want {
		t.Fatalf("missing server lifecycle spec for %s", protocol)
	}
}

func newProcessSupervisor(t *testing.T, starter *recordingProcessStarter) *Supervisor {
	t.Helper()

	supervisor, err := NewSupervisor(starter, nil, []ProtocolLifecycleSpec{
		{
			Protocol: ProtocolHysteria2,
			Mode:     LifecycleProcess,
			Start:    ProcessCommand{Name: "hysteria", Args: []string{"client", "-c", "h.yaml"}},
		},
		{
			Protocol: ProtocolReality,
			Mode:     LifecycleProcess,
			Start:    ProcessCommand{Name: "xray", Args: []string{"run", "-config", "reality.json"}},
		},
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	return supervisor
}

type recordingCommand struct {
	name string
	args []string
}

func (c recordingCommand) String() string {
	return strings.TrimSpace(c.name + " " + strings.Join(c.args, " "))
}

type recordingCommandRunner struct {
	commands []recordingCommand
	err      error
}

func (r *recordingCommandRunner) Run(ctx context.Context, name string, args ...string) error {
	r.commands = append(r.commands, recordingCommand{name: name, args: append([]string(nil), args...)})
	return r.err
}

type recordingProcessStarter struct {
	commands  []recordingCommand
	processes []*recordingProcess
	errors    map[string]error
}

func (s *recordingProcessStarter) Start(ctx context.Context, command ProcessCommand) (ManagedProcess, error) {
	recorded := recordingCommand{name: command.Name, args: append([]string(nil), command.Args...)}
	s.commands = append(s.commands, recorded)
	if err := s.errors[recorded.String()]; err != nil {
		return nil, err
	}
	process := &recordingProcess{}
	s.processes = append(s.processes, process)
	return process, nil
}

type recordingProcess struct {
	stopped bool
}

func (p *recordingProcess) Stop(ctx context.Context) error {
	p.stopped = true
	return nil
}

func commandStrings(commands []recordingCommand) []string {
	result := make([]string, 0, len(commands))
	for _, command := range commands {
		result = append(result, command.String())
	}
	return result
}
