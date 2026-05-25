package linuxgw

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"anixops-sd-wan/internal/policy"
)

func TestStreamDNSMasqJournalObservationsBuildsCommandAndStreams(t *testing.T) {
	command := &fakeDNSMasqJournalCommand{
		stdout: io.NopCloser(strings.NewReader(strings.Join([]string{
			`query[A] api.openai.com from 192.168.10.55`,
			`reply api.openai.com is 203.0.113.10`,
			`cached video.example is 2001:db8::20`,
		}, "\n"))),
	}
	var gotName string
	var gotArgs []string
	factory := func(ctx context.Context, name string, args ...string) (DNSMasqJournalCommand, error) {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return command, nil
	}

	var observed []policy.Request
	err := StreamDNSMasqJournalObservations(context.Background(), "tenant-a", func(ctx context.Context, request policy.Request) error {
		observed = append(observed, request)
		return nil
	}, DNSMasqJournalTailOptions{CommandFactory: factory})
	if err != nil {
		t.Fatalf("stream journal observations: %v", err)
	}
	if gotName != "journalctl" {
		t.Fatalf("expected journalctl command, got %q", gotName)
	}
	wantArgs := []string{"-f", "-u", "dnsmasq", "-o", "cat", "-n", "0"}
	if fmt.Sprint(gotArgs) != fmt.Sprint(wantArgs) {
		t.Fatalf("expected args %v, got %v", wantArgs, gotArgs)
	}
	if !command.started || !command.waited || command.stopped {
		t.Fatalf("unexpected command lifecycle: started=%v waited=%v stopped=%v", command.started, command.waited, command.stopped)
	}
	if len(observed) != 2 || observed[0].Domain != "api.openai.com" || observed[1].Domain != "video.example" {
		t.Fatalf("unexpected journal observations: %+v", observed)
	}
}

func TestStreamDNSMasqJournalObservationsUsesCustomCommandAndUnit(t *testing.T) {
	command := &fakeDNSMasqJournalCommand{stdout: io.NopCloser(strings.NewReader(""))}
	var gotName string
	var gotArgs []string
	factory := func(ctx context.Context, name string, args ...string) (DNSMasqJournalCommand, error) {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return command, nil
	}

	err := StreamDNSMasqJournalObservations(context.Background(), "tenant-a", func(ctx context.Context, request policy.Request) error {
		return nil
	}, DNSMasqJournalTailOptions{
		Unit:           "dnsmasq@lan.service",
		CommandName:    "/usr/bin/journalctl",
		CommandFactory: factory,
	})
	if err != nil {
		t.Fatalf("stream journal observations: %v", err)
	}
	if gotName != "/usr/bin/journalctl" {
		t.Fatalf("expected custom command name, got %q", gotName)
	}
	wantArgs := []string{"-f", "-u", "dnsmasq@lan.service", "-o", "cat", "-n", "0"}
	if fmt.Sprint(gotArgs) != fmt.Sprint(wantArgs) {
		t.Fatalf("expected args %v, got %v", wantArgs, gotArgs)
	}
}

func TestStreamDNSMasqJournalObservationsStopsCommandOnHandlerError(t *testing.T) {
	command := &fakeDNSMasqJournalCommand{
		stdout: io.NopCloser(strings.NewReader(`reply api.openai.com is 203.0.113.10` + "\n")),
	}
	handlerErr := errors.New("handler failed")
	err := StreamDNSMasqJournalObservations(context.Background(), "tenant-a", func(ctx context.Context, request policy.Request) error {
		return handlerErr
	}, DNSMasqJournalTailOptions{CommandFactory: fakeDNSMasqJournalFactory(command)})
	if !errors.Is(err, handlerErr) {
		t.Fatalf("expected handler error, got %v", err)
	}
	if !command.stopped || !command.waited {
		t.Fatalf("expected command stop and wait after handler error, got stopped=%v waited=%v", command.stopped, command.waited)
	}
}

func TestStreamDNSMasqJournalObservationsReturnsCommandErrors(t *testing.T) {
	factoryErr := errors.New("factory failed")
	err := StreamDNSMasqJournalObservations(context.Background(), "tenant-a", func(ctx context.Context, request policy.Request) error {
		return nil
	}, DNSMasqJournalTailOptions{
		CommandFactory: func(ctx context.Context, name string, args ...string) (DNSMasqJournalCommand, error) {
			return nil, factoryErr
		},
	})
	if !errors.Is(err, factoryErr) {
		t.Fatalf("expected factory error, got %v", err)
	}

	stdoutErr := errors.New("stdout failed")
	command := &fakeDNSMasqJournalCommand{stdoutErr: stdoutErr}
	err = StreamDNSMasqJournalObservations(context.Background(), "tenant-a", func(ctx context.Context, request policy.Request) error {
		return nil
	}, DNSMasqJournalTailOptions{CommandFactory: fakeDNSMasqJournalFactory(command)})
	if !errors.Is(err, stdoutErr) {
		t.Fatalf("expected stdout error, got %v", err)
	}

	startErr := errors.New("start failed")
	command = &fakeDNSMasqJournalCommand{stdout: io.NopCloser(strings.NewReader("")), startErr: startErr}
	err = StreamDNSMasqJournalObservations(context.Background(), "tenant-a", func(ctx context.Context, request policy.Request) error {
		return nil
	}, DNSMasqJournalTailOptions{CommandFactory: fakeDNSMasqJournalFactory(command)})
	if !errors.Is(err, startErr) {
		t.Fatalf("expected start error, got %v", err)
	}
	if command.waited {
		t.Fatal("command should not be waited when start fails")
	}

	waitErr := errors.New("wait failed")
	command = &fakeDNSMasqJournalCommand{stdout: io.NopCloser(strings.NewReader("")), waitErr: waitErr}
	err = StreamDNSMasqJournalObservations(context.Background(), "tenant-a", func(ctx context.Context, request policy.Request) error {
		return nil
	}, DNSMasqJournalTailOptions{CommandFactory: fakeDNSMasqJournalFactory(command)})
	if !errors.Is(err, waitErr) {
		t.Fatalf("expected wait error, got %v", err)
	}
}

func TestStreamDNSMasqJournalObservationsRejectsInvalidInputs(t *testing.T) {
	command := &fakeDNSMasqJournalCommand{stdout: io.NopCloser(strings.NewReader(""))}
	if err := StreamDNSMasqJournalObservations(context.Background(), "", func(ctx context.Context, request policy.Request) error {
		return nil
	}, DNSMasqJournalTailOptions{CommandFactory: fakeDNSMasqJournalFactory(command)}); err == nil {
		t.Fatal("expected missing tenant to be rejected")
	}
	if err := StreamDNSMasqJournalObservations(context.Background(), "tenant-a", nil, DNSMasqJournalTailOptions{CommandFactory: fakeDNSMasqJournalFactory(command)}); err == nil {
		t.Fatal("expected missing handler to be rejected")
	}
}

func fakeDNSMasqJournalFactory(command *fakeDNSMasqJournalCommand) DNSMasqJournalCommandFactory {
	return func(ctx context.Context, name string, args ...string) (DNSMasqJournalCommand, error) {
		return command, nil
	}
}

type fakeDNSMasqJournalCommand struct {
	stdout    io.ReadCloser
	stdoutErr error
	startErr  error
	waitErr   error
	stopErr   error
	started   bool
	waited    bool
	stopped   bool
}

func (c *fakeDNSMasqJournalCommand) StdoutPipe() (io.ReadCloser, error) {
	if c.stdoutErr != nil {
		return nil, c.stdoutErr
	}
	if c.stdout == nil {
		c.stdout = io.NopCloser(strings.NewReader(""))
	}
	return c.stdout, nil
}

func (c *fakeDNSMasqJournalCommand) Start() error {
	if c.startErr != nil {
		return c.startErr
	}
	c.started = true
	return nil
}

func (c *fakeDNSMasqJournalCommand) Wait() error {
	c.waited = true
	return c.waitErr
}

func (c *fakeDNSMasqJournalCommand) Stop() error {
	c.stopped = true
	return c.stopErr
}
