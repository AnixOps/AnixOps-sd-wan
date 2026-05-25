package linuxgw

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

type DNSMasqJournalCommand interface {
	StdoutPipe() (io.ReadCloser, error)
	Start() error
	Wait() error
	Stop() error
}

type DNSMasqJournalCommandFactory func(context.Context, string, ...string) (DNSMasqJournalCommand, error)

type DNSMasqJournalTailOptions struct {
	Unit           string
	CommandName    string
	CommandFactory DNSMasqJournalCommandFactory
}

func StreamDNSMasqJournalObservations(ctx context.Context, tenantID string, handler DNSMasqObservationHandler, options DNSMasqJournalTailOptions) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return fmt.Errorf("tenant id is required")
	}
	if handler == nil {
		return fmt.Errorf("dnsmasq observation handler is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	commandName := strings.TrimSpace(options.CommandName)
	if commandName == "" {
		commandName = "journalctl"
	}
	unit := strings.TrimSpace(options.Unit)
	if unit == "" {
		unit = "dnsmasq"
	}
	factory := options.CommandFactory
	if factory == nil {
		factory = newExecDNSMasqJournalCommand
	}

	command, err := factory(ctx, commandName, "-f", "-u", unit, "-o", "cat", "-n", "0")
	if err != nil {
		return fmt.Errorf("create dnsmasq journal command: %w", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open dnsmasq journal stdout: %w", err)
	}
	defer stdout.Close()
	if err := command.Start(); err != nil {
		return fmt.Errorf("start dnsmasq journal command: %w", err)
	}

	streamErr := StreamDNSMasqLogObservations(ctx, tenantID, stdout, handler)
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
		return fmt.Errorf("wait dnsmasq journal command: %w", waitErr)
	}
	return nil
}

type execDNSMasqJournalCommand struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
}

func newExecDNSMasqJournalCommand(ctx context.Context, name string, args ...string) (DNSMasqJournalCommand, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	commandCtx, cancel := context.WithCancel(ctx)
	return &execDNSMasqJournalCommand{
		cmd:    exec.CommandContext(commandCtx, name, args...),
		cancel: cancel,
	}, nil
}

func (c *execDNSMasqJournalCommand) StdoutPipe() (io.ReadCloser, error) {
	return c.cmd.StdoutPipe()
}

func (c *execDNSMasqJournalCommand) Start() error {
	return c.cmd.Start()
}

func (c *execDNSMasqJournalCommand) Wait() error {
	return c.cmd.Wait()
}

func (c *execDNSMasqJournalCommand) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}
