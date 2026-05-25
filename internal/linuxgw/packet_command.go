package linuxgw

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

type ConntrackObservationCommand interface {
	StdoutPipe() (io.ReadCloser, error)
	Start() error
	Wait() error
	Stop() error
}

type ConntrackObservationCommandFactory func(context.Context, string, ...string) (ConntrackObservationCommand, error)

type ConntrackCommandOptions struct {
	PacketOptions  PacketObservationOptions
	CommandName    string
	Args           []string
	CommandFactory ConntrackObservationCommandFactory
}

func StreamConntrackCommandObservations(ctx context.Context, tenantID string, handler PacketObservationHandler, options ConntrackCommandOptions) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return fmt.Errorf("tenant id is required")
	}
	if handler == nil {
		return fmt.Errorf("packet observation handler is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	commandName := strings.TrimSpace(options.CommandName)
	if commandName == "" {
		commandName = "conntrack"
	}
	args := append([]string(nil), options.Args...)
	if len(args) == 0 {
		args = []string{"-E", "-o", "extended"}
	}
	factory := options.CommandFactory
	if factory == nil {
		factory = newExecConntrackObservationCommand
	}

	command, err := factory(ctx, commandName, args...)
	if err != nil {
		return fmt.Errorf("create conntrack command: %w", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open conntrack stdout: %w", err)
	}
	defer stdout.Close()
	if err := command.Start(); err != nil {
		return fmt.Errorf("start conntrack command: %w", err)
	}

	streamErr := StreamConntrackObservations(ctx, tenantID, stdout, options.PacketOptions, handler)
	if streamErr != nil {
		_ = command.Stop()
	}
	waitErr := command.Wait()
	if streamErr != nil {
		return streamErr
	}
	if waitErr != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fmt.Errorf("wait conntrack command: %w", waitErr)
	}
	return nil
}

type execConntrackObservationCommand struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
}

func newExecConntrackObservationCommand(ctx context.Context, name string, args ...string) (ConntrackObservationCommand, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	commandCtx, cancel := context.WithCancel(ctx)
	return &execConntrackObservationCommand{
		cmd:    exec.CommandContext(commandCtx, name, args...),
		cancel: cancel,
	}, nil
}

func (c *execConntrackObservationCommand) StdoutPipe() (io.ReadCloser, error) {
	return c.cmd.StdoutPipe()
}

func (c *execConntrackObservationCommand) Start() error {
	return c.cmd.Start()
}

func (c *execConntrackObservationCommand) Wait() error {
	return c.cmd.Wait()
}

func (c *execConntrackObservationCommand) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}
