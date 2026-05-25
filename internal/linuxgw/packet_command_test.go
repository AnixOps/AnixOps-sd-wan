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

func TestStreamConntrackCommandObservationsBuildsCommandAndStreams(t *testing.T) {
	command := &fakeConntrackObservationCommand{
		stdout: io.NopCloser(strings.NewReader(strings.Join([]string{
			`tcp 6 120 src=192.168.10.55 dst=203.0.113.44 sport=53001 dport=443`,
			`tcp 6 120 src=10.99.0.10 dst=203.0.113.45 sport=53002 dport=443`,
			`udp 17 30 src=192.168.10.56 dst=2001:db8::44 sport=53003 dport=443`,
		}, "\n"))),
	}
	var gotName string
	var gotArgs []string
	factory := func(ctx context.Context, name string, args ...string) (ConntrackObservationCommand, error) {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return command, nil
	}

	var observed []policy.Request
	err := StreamConntrackCommandObservations(context.Background(), "tenant-a", func(ctx context.Context, request policy.Request) error {
		observed = append(observed, request)
		return nil
	}, ConntrackCommandOptions{
		PacketOptions:  PacketObservationOptions{SourceCIDRs: []string{"192.168.10.0/24"}},
		CommandFactory: factory,
	})
	if err != nil {
		t.Fatalf("stream conntrack command observations: %v", err)
	}
	if gotName != "conntrack" {
		t.Fatalf("expected conntrack command, got %q", gotName)
	}
	wantArgs := []string{"-E", "-o", "extended"}
	if fmt.Sprint(gotArgs) != fmt.Sprint(wantArgs) {
		t.Fatalf("expected args %v, got %v", wantArgs, gotArgs)
	}
	if !command.started || !command.waited || command.stopped {
		t.Fatalf("unexpected command lifecycle: started=%v waited=%v stopped=%v", command.started, command.waited, command.stopped)
	}
	if len(observed) != 2 || observed[0].IP != "203.0.113.44" || observed[1].IP != "2001:db8::44" {
		t.Fatalf("unexpected conntrack command observations: %+v", observed)
	}
}

func TestStreamConntrackCommandObservationsUsesCustomCommandAndArgs(t *testing.T) {
	command := &fakeConntrackObservationCommand{stdout: io.NopCloser(strings.NewReader(""))}
	var gotName string
	var gotArgs []string
	factory := func(ctx context.Context, name string, args ...string) (ConntrackObservationCommand, error) {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return command, nil
	}

	err := StreamConntrackCommandObservations(context.Background(), "tenant-a", func(ctx context.Context, request policy.Request) error {
		return nil
	}, ConntrackCommandOptions{
		CommandName:    "/usr/sbin/conntrack",
		Args:           []string{"-E", "-p", "tcp"},
		CommandFactory: factory,
	})
	if err != nil {
		t.Fatalf("stream conntrack command observations: %v", err)
	}
	if gotName != "/usr/sbin/conntrack" {
		t.Fatalf("expected custom command name, got %q", gotName)
	}
	wantArgs := []string{"-E", "-p", "tcp"}
	if fmt.Sprint(gotArgs) != fmt.Sprint(wantArgs) {
		t.Fatalf("expected args %v, got %v", wantArgs, gotArgs)
	}
}

func TestStreamConntrackCommandObservationsStopsCommandOnHandlerError(t *testing.T) {
	command := &fakeConntrackObservationCommand{
		stdout: io.NopCloser(strings.NewReader(`tcp 6 120 src=192.168.10.55 dst=203.0.113.44 sport=53001 dport=443` + "\n")),
	}
	handlerErr := errors.New("handler failed")
	err := StreamConntrackCommandObservations(context.Background(), "tenant-a", func(ctx context.Context, request policy.Request) error {
		return handlerErr
	}, ConntrackCommandOptions{CommandFactory: fakeConntrackObservationFactory(command)})
	if !errors.Is(err, handlerErr) {
		t.Fatalf("expected handler error, got %v", err)
	}
	if !command.stopped || !command.waited {
		t.Fatalf("expected command stop and wait after handler error, got stopped=%v waited=%v", command.stopped, command.waited)
	}
}

func TestStreamConntrackCommandObservationsReturnsCommandErrors(t *testing.T) {
	factoryErr := errors.New("factory failed")
	err := StreamConntrackCommandObservations(context.Background(), "tenant-a", func(ctx context.Context, request policy.Request) error {
		return nil
	}, ConntrackCommandOptions{
		CommandFactory: func(ctx context.Context, name string, args ...string) (ConntrackObservationCommand, error) {
			return nil, factoryErr
		},
	})
	if !errors.Is(err, factoryErr) {
		t.Fatalf("expected factory error, got %v", err)
	}

	stdoutErr := errors.New("stdout failed")
	command := &fakeConntrackObservationCommand{stdoutErr: stdoutErr}
	err = StreamConntrackCommandObservations(context.Background(), "tenant-a", func(ctx context.Context, request policy.Request) error {
		return nil
	}, ConntrackCommandOptions{CommandFactory: fakeConntrackObservationFactory(command)})
	if !errors.Is(err, stdoutErr) {
		t.Fatalf("expected stdout error, got %v", err)
	}

	startErr := errors.New("start failed")
	command = &fakeConntrackObservationCommand{stdout: io.NopCloser(strings.NewReader("")), startErr: startErr}
	err = StreamConntrackCommandObservations(context.Background(), "tenant-a", func(ctx context.Context, request policy.Request) error {
		return nil
	}, ConntrackCommandOptions{CommandFactory: fakeConntrackObservationFactory(command)})
	if !errors.Is(err, startErr) {
		t.Fatalf("expected start error, got %v", err)
	}
	if command.waited {
		t.Fatal("command should not be waited when start fails")
	}

	waitErr := errors.New("wait failed")
	command = &fakeConntrackObservationCommand{stdout: io.NopCloser(strings.NewReader("")), waitErr: waitErr}
	err = StreamConntrackCommandObservations(context.Background(), "tenant-a", func(ctx context.Context, request policy.Request) error {
		return nil
	}, ConntrackCommandOptions{CommandFactory: fakeConntrackObservationFactory(command)})
	if !errors.Is(err, waitErr) {
		t.Fatalf("expected wait error, got %v", err)
	}
}

func TestStreamConntrackCommandObservationsRejectsInvalidInputs(t *testing.T) {
	command := &fakeConntrackObservationCommand{stdout: io.NopCloser(strings.NewReader(""))}
	if err := StreamConntrackCommandObservations(context.Background(), "", func(ctx context.Context, request policy.Request) error {
		return nil
	}, ConntrackCommandOptions{CommandFactory: fakeConntrackObservationFactory(command)}); err == nil {
		t.Fatal("expected missing tenant to be rejected")
	}
	if err := StreamConntrackCommandObservations(context.Background(), "tenant-a", nil, ConntrackCommandOptions{CommandFactory: fakeConntrackObservationFactory(command)}); err == nil {
		t.Fatal("expected missing handler to be rejected")
	}
	if err := StreamConntrackCommandObservations(context.Background(), "tenant-a", func(ctx context.Context, request policy.Request) error {
		return nil
	}, ConntrackCommandOptions{
		PacketOptions:  PacketObservationOptions{SourceCIDRs: []string{"not-cidr"}},
		CommandFactory: fakeConntrackObservationFactory(command),
	}); err == nil {
		t.Fatal("expected invalid source cidr to be rejected")
	}
}

func fakeConntrackObservationFactory(command *fakeConntrackObservationCommand) ConntrackObservationCommandFactory {
	return func(ctx context.Context, name string, args ...string) (ConntrackObservationCommand, error) {
		return command, nil
	}
}

type fakeConntrackObservationCommand struct {
	stdout    io.ReadCloser
	stdoutErr error
	startErr  error
	waitErr   error
	stopErr   error
	started   bool
	waited    bool
	stopped   bool
}

func (c *fakeConntrackObservationCommand) StdoutPipe() (io.ReadCloser, error) {
	if c.stdoutErr != nil {
		return nil, c.stdoutErr
	}
	if c.stdout == nil {
		c.stdout = io.NopCloser(strings.NewReader(""))
	}
	return c.stdout, nil
}

func (c *fakeConntrackObservationCommand) Start() error {
	if c.startErr != nil {
		return c.startErr
	}
	c.started = true
	return nil
}

func (c *fakeConntrackObservationCommand) Wait() error {
	c.waited = true
	return c.waitErr
}

func (c *fakeConntrackObservationCommand) Stop() error {
	c.stopped = true
	return c.stopErr
}
