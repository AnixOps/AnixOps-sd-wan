package transport

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

type LifecycleMode string

const (
	LifecycleCommand LifecycleMode = "command"
	LifecycleProcess LifecycleMode = "process"
)

type ProcessCommand struct {
	Name string   `json:"name"`
	Args []string `json:"args,omitempty"`
}

func (c ProcessCommand) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("command name is required")
	}
	return nil
}

type ProtocolLifecycleSpec struct {
	Protocol Protocol       `json:"protocol"`
	Mode     LifecycleMode  `json:"mode"`
	Start    ProcessCommand `json:"start"`
	Stop     ProcessCommand `json:"stop,omitempty"`
}

func (s ProtocolLifecycleSpec) Validate() error {
	if !KnownProtocol(s.Protocol) {
		return fmt.Errorf("unknown protocol %q", s.Protocol)
	}
	switch s.Mode {
	case LifecycleCommand, LifecycleProcess:
	default:
		return fmt.Errorf("unsupported lifecycle mode %q", s.Mode)
	}
	if err := s.Start.Validate(); err != nil {
		return fmt.Errorf("start command: %w", err)
	}
	if s.Mode == LifecycleCommand {
		if err := s.Stop.Validate(); err != nil {
			return fmt.Errorf("stop command: %w", err)
		}
	}
	if s.Stop.Name != "" {
		if err := s.Stop.Validate(); err != nil {
			return fmt.Errorf("stop command: %w", err)
		}
	}
	return nil
}

type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) error
}

type ExecCommandRunner struct{}

func (ExecCommandRunner) Run(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run()
}

type ManagedProcess interface {
	Stop(context.Context) error
}

type ProcessStarter interface {
	Start(context.Context, ProcessCommand) (ManagedProcess, error)
}

type ExecProcessStarter struct{}

func (ExecProcessStarter) Start(ctx context.Context, command ProcessCommand) (ManagedProcess, error) {
	if err := command.Validate(); err != nil {
		return nil, err
	}
	processCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(processCtx, command.Name, command.Args...)
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}
	process := &execManagedProcess{
		cancel: cancel,
		done:   make(chan error, 1),
	}
	go func() {
		process.done <- cmd.Wait()
	}()
	return process, nil
}

type execManagedProcess struct {
	cancel  context.CancelFunc
	done    chan error
	waitMu  sync.Mutex
	waited  bool
	waitErr error
}

func (p *execManagedProcess) Stop(ctx context.Context) error {
	p.cancel()
	if err := p.wait(ctx); err != nil {
		return err
	}
	return nil
}

func (p *execManagedProcess) wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		p.waitMu.Lock()
		defer p.waitMu.Unlock()
		if !p.waited {
			p.waitErr = <-p.done
			p.waited = true
		}
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type Supervisor struct {
	mu        sync.Mutex
	starter   ProcessStarter
	runner    CommandRunner
	specs     map[Protocol]ProtocolLifecycleSpec
	active    Protocol
	activeSet bool
	process   ManagedProcess
}

func NewSupervisor(starter ProcessStarter, runner CommandRunner, specs []ProtocolLifecycleSpec) (*Supervisor, error) {
	if starter == nil {
		starter = ExecProcessStarter{}
	}
	if runner == nil {
		runner = ExecCommandRunner{}
	}
	byProtocol := make(map[Protocol]ProtocolLifecycleSpec, len(specs))
	for _, spec := range specs {
		if err := spec.Validate(); err != nil {
			return nil, err
		}
		if _, exists := byProtocol[spec.Protocol]; exists {
			return nil, fmt.Errorf("duplicate lifecycle spec for protocol %s", spec.Protocol)
		}
		byProtocol[spec.Protocol] = spec
	}
	if len(byProtocol) == 0 {
		return nil, fmt.Errorf("at least one protocol lifecycle spec is required")
	}
	return &Supervisor{
		starter: starter,
		runner:  runner,
		specs:   byProtocol,
	}, nil
}

func (s *Supervisor) Active() (Protocol, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.active, s.activeSet
}

func (s *Supervisor) Activate(ctx context.Context, protocol Protocol) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.activeSet && s.active == protocol {
		return nil
	}
	spec, exists := s.specs[protocol]
	if !exists {
		return fmt.Errorf("no lifecycle spec for protocol %s", protocol)
	}

	previous := s.active
	hadPrevious := s.activeSet
	if hadPrevious {
		if err := s.stopLocked(ctx); err != nil {
			return fmt.Errorf("stop active protocol %s: %w", previous, err)
		}
	}

	process, err := s.startLocked(ctx, spec)
	if err != nil {
		if hadPrevious {
			if restoreErr := s.restoreLocked(ctx, previous); restoreErr != nil {
				return fmt.Errorf("activate protocol %s: %w; restore protocol %s: %v", protocol, err, previous, restoreErr)
			}
		}
		return fmt.Errorf("activate protocol %s: %w", protocol, err)
	}
	s.active = protocol
	s.activeSet = true
	s.process = process
	return nil
}

func (s *Supervisor) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.activeSet {
		return nil
	}
	return s.stopLocked(ctx)
}

func (s *Supervisor) restoreLocked(ctx context.Context, protocol Protocol) error {
	spec, exists := s.specs[protocol]
	if !exists {
		return fmt.Errorf("no lifecycle spec for protocol %s", protocol)
	}
	process, err := s.startLocked(ctx, spec)
	if err != nil {
		return err
	}
	s.active = protocol
	s.activeSet = true
	s.process = process
	return nil
}

func (s *Supervisor) startLocked(ctx context.Context, spec ProtocolLifecycleSpec) (ManagedProcess, error) {
	switch spec.Mode {
	case LifecycleCommand:
		if err := s.runner.Run(ctx, spec.Start.Name, spec.Start.Args...); err != nil {
			return nil, err
		}
		return nil, nil
	case LifecycleProcess:
		return s.starter.Start(ctx, spec.Start)
	default:
		return nil, fmt.Errorf("unsupported lifecycle mode %q", spec.Mode)
	}
}

func (s *Supervisor) stopLocked(ctx context.Context) error {
	spec := s.specs[s.active]
	var stopErr error
	if s.process != nil {
		stopErr = s.process.Stop(ctx)
	}
	if spec.Stop.Name != "" {
		if err := s.runner.Run(ctx, spec.Stop.Name, spec.Stop.Args...); err != nil && stopErr == nil {
			stopErr = err
		}
	}
	if stopErr != nil {
		return stopErr
	}
	s.active = ""
	s.activeSet = false
	s.process = nil
	return nil
}

func DefaultLifecycleSpecs(configDir string) []ProtocolLifecycleSpec {
	configDir = normalizeConfigDir(configDir)
	return []ProtocolLifecycleSpec{
		{
			Protocol: ProtocolWireGuard,
			Mode:     LifecycleCommand,
			Start:    ProcessCommand{Name: "wg-quick", Args: []string{"up", filepath.Join(configDir, WireGuardConfigFile)}},
			Stop:     ProcessCommand{Name: "wg-quick", Args: []string{"down", filepath.Join(configDir, WireGuardConfigFile)}},
		},
		{
			Protocol: ProtocolHysteria2,
			Mode:     LifecycleProcess,
			Start:    ProcessCommand{Name: "hysteria", Args: []string{"client", "-c", filepath.Join(configDir, Hysteria2ConfigFile)}},
		},
		{
			Protocol: ProtocolReality,
			Mode:     LifecycleProcess,
			Start:    ProcessCommand{Name: "xray", Args: []string{"run", "-config", filepath.Join(configDir, RealityConfigFile)}},
		},
		{
			Protocol: ProtocolTUIC,
			Mode:     LifecycleProcess,
			Start:    ProcessCommand{Name: "tuic-client", Args: []string{"-c", filepath.Join(configDir, TUICConfigFile)}},
		},
	}
}

func DefaultServerLifecycleSpecs(configDir string) []ProtocolLifecycleSpec {
	configDir = normalizeConfigDir(configDir)
	return []ProtocolLifecycleSpec{
		{
			Protocol: ProtocolHysteria2,
			Mode:     LifecycleProcess,
			Start:    ProcessCommand{Name: "hysteria", Args: []string{"server", "-c", filepath.Join(configDir, Hysteria2ConfigFile)}},
		},
		{
			Protocol: ProtocolReality,
			Mode:     LifecycleProcess,
			Start:    ProcessCommand{Name: "xray", Args: []string{"run", "-config", filepath.Join(configDir, RealityConfigFile)}},
		},
		{
			Protocol: ProtocolTUIC,
			Mode:     LifecycleProcess,
			Start:    ProcessCommand{Name: "tuic-server", Args: []string{"-c", filepath.Join(configDir, TUICConfigFile)}},
		},
	}
}
