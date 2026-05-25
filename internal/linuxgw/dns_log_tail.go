package linuxgw

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type DNSMasqLogFileTailOptions struct {
	PollInterval time.Duration
}

func StreamDNSMasqLogFileObservations(ctx context.Context, tenantID, logPath string, handler DNSMasqObservationHandler, options DNSMasqLogFileTailOptions) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return fmt.Errorf("tenant id is required")
	}
	logPath = strings.TrimSpace(logPath)
	if logPath == "" {
		return fmt.Errorf("dnsmasq log path is required")
	}
	if handler == nil {
		return fmt.Errorf("dnsmasq observation handler is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	pollInterval := options.PollInterval
	if pollInterval <= 0 {
		pollInterval = 250 * time.Millisecond
	}

	file, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("open dnsmasq log file: %w", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			if err := handleDNSMasqLogTailLine(ctx, tenantID, line, handler); err != nil {
				return err
			}
		}
		if err == nil {
			continue
		}
		if err != io.EOF {
			return err
		}
		if err := resetDNSMasqLogTailAfterTruncate(file, &reader); err != nil {
			return err
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func handleDNSMasqLogTailLine(ctx context.Context, tenantID, line string, handler DNSMasqObservationHandler) error {
	request, ok, err := ParseDNSMasqLogLine(tenantID, line)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	return handler(ctx, request)
}

func resetDNSMasqLogTailAfterTruncate(file *os.File, reader **bufio.Reader) error {
	position, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("read dnsmasq log offset: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat dnsmasq log file: %w", err)
	}
	if info.Size() >= position {
		return nil
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("reset truncated dnsmasq log file: %w", err)
	}
	*reader = bufio.NewReader(file)
	return nil
}
