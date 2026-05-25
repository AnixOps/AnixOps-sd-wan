package linuxgw

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"anixops-sd-wan/internal/policy"
)

type DNSMasqObservationHandler func(context.Context, policy.Request) error

func ParseDNSMasqLogObservations(tenantID string, reader io.Reader) ([]policy.Request, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	if reader == nil {
		return nil, fmt.Errorf("dnsmasq log reader is required")
	}

	var observations []policy.Request
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		request, ok, err := ParseDNSMasqLogLine(tenantID, scanner.Text())
		if err != nil {
			return nil, err
		}
		if ok {
			observations = append(observations, request)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return observations, nil
}

func StreamDNSMasqLogObservations(ctx context.Context, tenantID string, reader io.Reader, handler DNSMasqObservationHandler) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return fmt.Errorf("tenant id is required")
	}
	if reader == nil {
		return fmt.Errorf("dnsmasq log reader is required")
	}
	if handler == nil {
		return fmt.Errorf("dnsmasq observation handler is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		request, ok, err := ParseDNSMasqLogLine(tenantID, scanner.Text())
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if err := handler(ctx, request); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func ParseDNSMasqLogLine(tenantID, line string) (policy.Request, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return policy.Request{}, false, fmt.Errorf("tenant id is required")
	}
	payload := strings.TrimSpace(line)
	if index := strings.Index(payload, ": "); index >= 0 {
		payload = strings.TrimSpace(payload[index+2:])
	}
	fields := strings.Fields(payload)
	if len(fields) < 4 {
		return policy.Request{}, false, nil
	}
	switch fields[0] {
	case "reply", "cached", "config":
	default:
		return policy.Request{}, false, nil
	}
	if fields[2] != "is" {
		return policy.Request{}, false, nil
	}
	ip := net.ParseIP(fields[3])
	if ip == nil {
		return policy.Request{}, false, nil
	}
	domain := strings.TrimSuffix(strings.TrimSpace(fields[1]), ".")
	if domain == "" {
		return policy.Request{}, false, nil
	}
	return policy.Request{
		TenantID: tenantID,
		Domain:   domain,
		IP:       ip.String(),
	}, true, nil
}
