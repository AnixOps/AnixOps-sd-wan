package linuxgw

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anixops-sd-wan/internal/policy"
)

func TestStreamDNSMasqLogFileObservationsReadsExistingAndAppendedLines(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "dnsmasq.log")
	if err := os.WriteFile(logPath, []byte(strings.Join([]string{
		`dnsmasq[100]: query[A] api.openai.com from 192.168.10.55`,
		`dnsmasq[100]: reply api.openai.com is 203.0.113.10`,
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var observed []policy.Request
	done := make(chan error, 1)
	go func() {
		done <- StreamDNSMasqLogFileObservations(ctx, "tenant-a", logPath, func(ctx context.Context, request policy.Request) error {
			observed = append(observed, request)
			if len(observed) == 1 {
				if err := appendDNSMasqTestLine(logPath, `dnsmasq[100]: cached video.example is 2001:db8::20`); err != nil {
					return err
				}
			}
			if len(observed) == 2 {
				cancel()
			}
			return nil
		}, DNSMasqLogFileTailOptions{PollInterval: time.Millisecond})
	}()

	err := waitDNSMasqTailDone(t, done)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation after observations, got %v", err)
	}
	if len(observed) != 2 {
		t.Fatalf("expected two observations, got %+v", observed)
	}
	if observed[0].Domain != "api.openai.com" || observed[0].IP != "203.0.113.10" {
		t.Fatalf("unexpected first observation: %+v", observed[0])
	}
	if observed[1].Domain != "video.example" || observed[1].IP != "2001:db8::20" {
		t.Fatalf("unexpected appended observation: %+v", observed[1])
	}
}

func TestStreamDNSMasqLogFileObservationsReturnsHandlerError(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "dnsmasq.log")
	if err := os.WriteFile(logPath, []byte(`dnsmasq[100]: reply api.openai.com is 203.0.113.10`+"\n"), 0o644); err != nil {
		t.Fatalf("write log file: %v", err)
	}
	handlerErr := errors.New("handler failed")

	err := StreamDNSMasqLogFileObservations(context.Background(), "tenant-a", logPath, func(ctx context.Context, request policy.Request) error {
		return handlerErr
	}, DNSMasqLogFileTailOptions{PollInterval: time.Millisecond})
	if !errors.Is(err, handlerErr) {
		t.Fatalf("expected handler error, got %v", err)
	}
}

func TestStreamDNSMasqLogFileObservationsHonorsCanceledContext(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "dnsmasq.log")
	if err := os.WriteFile(logPath, []byte(`dnsmasq[100]: reply api.openai.com is 203.0.113.10`+"\n"), 0o644); err != nil {
		t.Fatalf("write log file: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := StreamDNSMasqLogFileObservations(ctx, "tenant-a", logPath, func(ctx context.Context, request policy.Request) error {
		t.Fatal("handler should not be called after context cancellation")
		return nil
	}, DNSMasqLogFileTailOptions{PollInterval: time.Millisecond})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestStreamDNSMasqLogFileObservationsRejectsInvalidInputs(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "dnsmasq.log")
	if err := os.WriteFile(logPath, nil, 0o644); err != nil {
		t.Fatalf("write log file: %v", err)
	}
	if err := StreamDNSMasqLogFileObservations(context.Background(), "", logPath, func(ctx context.Context, request policy.Request) error {
		return nil
	}, DNSMasqLogFileTailOptions{}); err == nil {
		t.Fatal("expected missing tenant to be rejected")
	}
	if err := StreamDNSMasqLogFileObservations(context.Background(), "tenant-a", "", func(ctx context.Context, request policy.Request) error {
		return nil
	}, DNSMasqLogFileTailOptions{}); err == nil {
		t.Fatal("expected missing log path to be rejected")
	}
	if err := StreamDNSMasqLogFileObservations(context.Background(), "tenant-a", logPath, nil, DNSMasqLogFileTailOptions{}); err == nil {
		t.Fatal("expected missing handler to be rejected")
	}
	if err := StreamDNSMasqLogFileObservations(context.Background(), "tenant-a", filepath.Join(t.TempDir(), "missing.log"), func(ctx context.Context, request policy.Request) error {
		return nil
	}, DNSMasqLogFileTailOptions{}); err == nil {
		t.Fatal("expected missing log file to be rejected")
	}
}

func TestStreamDNSMasqLogFileObservationsResetsAfterTruncate(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "dnsmasq.log")
	if err := os.WriteFile(logPath, []byte(`dnsmasq[100]: reply old-long-domain.example is 203.0.113.1`+"\n"), 0o644); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var observed []policy.Request
	done := make(chan error, 1)
	go func() {
		done <- StreamDNSMasqLogFileObservations(ctx, "tenant-a", logPath, func(ctx context.Context, request policy.Request) error {
			observed = append(observed, request)
			if len(observed) == 1 {
				if err := os.WriteFile(logPath, []byte(`dnsmasq[100]: reply new.example is 203.0.113.2`+"\n"), 0o644); err != nil {
					return err
				}
			}
			if len(observed) == 2 {
				cancel()
			}
			return nil
		}, DNSMasqLogFileTailOptions{PollInterval: time.Millisecond})
	}()

	err := waitDNSMasqTailDone(t, done)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation after truncate observations, got %v", err)
	}
	if len(observed) != 2 || observed[0].Domain != "old-long-domain.example" || observed[1].Domain != "new.example" {
		t.Fatalf("expected old and truncated new observations, got %+v", observed)
	}
}

func appendDNSMasqTestLine(logPath, line string) error {
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.WriteString(line + "\n"); err != nil {
		return err
	}
	return nil
}

func waitDNSMasqTailDone(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for dnsmasq log tail")
		return nil
	}
}
