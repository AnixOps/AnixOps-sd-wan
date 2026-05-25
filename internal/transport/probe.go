package transport

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const probePayload = "anixops-probe"

type ProbeTarget struct {
	Network string
	Address string
	Timeout time.Duration
}

type ProbeResult struct {
	Network   string
	Address   string
	RTTMillis int
	Success   bool
	Error     string
	CheckedAt time.Time
}

type NetworkProber struct{}

type Prober interface {
	Probe(context.Context, ProbeTarget, time.Time) ProbeResult
}

type SignalHandler func(Signals)

func (NetworkProber) Probe(ctx context.Context, target ProbeTarget, now time.Time) ProbeResult {
	result := ProbeResult{
		Network:   strings.ToLower(strings.TrimSpace(target.Network)),
		Address:   strings.TrimSpace(target.Address),
		CheckedAt: now,
	}
	if result.Network == "" {
		result.Error = "probe network is required"
		return result
	}
	if result.Address == "" {
		result.Error = "probe address is required"
		return result
	}
	timeout := target.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	started := time.Now()
	var err error
	switch result.Network {
	case "tcp", "tcp4", "tcp6":
		err = probeTCP(probeCtx, result.Network, result.Address)
	case "udp", "udp4", "udp6":
		err = probeUDP(probeCtx, result.Network, result.Address, timeout)
	default:
		err = fmt.Errorf("unsupported probe network %q", result.Network)
	}
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Success = true
	result.RTTMillis = int(time.Since(started).Milliseconds())
	return result
}

func SignalsFromProbeResults(linkClass LinkClass, results []ProbeResult) Signals {
	signals := Signals{LinkClass: linkClass}
	if signals.LinkClass == "" {
		signals.LinkClass = LinkUnknown
	}
	if len(results) == 0 {
		return signals
	}

	failures := 0
	successes := 0
	totalRTT := 0
	for _, result := range results {
		if !result.Success {
			failures++
			continue
		}
		successes++
		totalRTT += result.RTTMillis
		if strings.HasPrefix(result.Network, "udp") {
			signals.UDPAvailable = true
		}
	}
	if successes > 0 {
		signals.RTTMillis = totalRTT / successes
	}
	signals.PacketLossPermil = failures * 1000 / len(results)
	signals.QoSRisk = signals.PacketLossPermil >= 100 || signals.RTTMillis >= 250
	return signals
}

func RunProbeLoop(ctx context.Context, prober Prober, targets []ProbeTarget, linkClass LinkClass, interval time.Duration, handle SignalHandler) error {
	if prober == nil {
		return fmt.Errorf("prober is required")
	}
	if len(targets) == 0 {
		return fmt.Errorf("at least one probe target is required")
	}
	if interval <= 0 {
		return fmt.Errorf("probe interval must be positive")
	}
	if handle == nil {
		return fmt.Errorf("signal handler is required")
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		now := time.Now().UTC()
		results := make([]ProbeResult, 0, len(targets))
		for _, target := range targets {
			results = append(results, prober.Probe(ctx, target, now))
		}
		handle(SignalsFromProbeResults(linkClass, results))

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func probeTCP(ctx context.Context, network, address string) error {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return err
	}
	return conn.Close()
}

func probeUDP(ctx context.Context, network, address string, timeout time.Duration) error {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return err
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err := conn.Write([]byte(probePayload)); err != nil {
		return err
	}
	buf := make([]byte, len(probePayload))
	_, err = conn.Read(buf)
	return err
}
