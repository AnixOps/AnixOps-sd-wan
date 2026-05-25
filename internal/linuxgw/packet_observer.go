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

type PacketObservationOptions struct {
	SourceCIDRs []string
}

type PacketObservationHandler func(context.Context, policy.Request) error

func ParseConntrackObservations(tenantID string, reader io.Reader, options PacketObservationOptions) ([]policy.Request, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	if reader == nil {
		return nil, fmt.Errorf("conntrack reader is required")
	}
	sourceNetworks, err := parsePacketObservationSourceNetworks(options)
	if err != nil {
		return nil, err
	}

	var observations []policy.Request
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		request, ok, err := parseConntrackLineWithSources(tenantID, scanner.Text(), sourceNetworks)
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

func StreamConntrackObservations(ctx context.Context, tenantID string, reader io.Reader, options PacketObservationOptions, handler PacketObservationHandler) error {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return fmt.Errorf("tenant id is required")
	}
	if reader == nil {
		return fmt.Errorf("conntrack reader is required")
	}
	if handler == nil {
		return fmt.Errorf("packet observation handler is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	sourceNetworks, err := parsePacketObservationSourceNetworks(options)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		request, ok, err := parseConntrackLineWithSources(tenantID, scanner.Text(), sourceNetworks)
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

func ParseConntrackLine(tenantID string, line string, options PacketObservationOptions) (policy.Request, bool, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return policy.Request{}, false, fmt.Errorf("tenant id is required")
	}
	sourceNetworks, err := parsePacketObservationSourceNetworks(options)
	if err != nil {
		return policy.Request{}, false, err
	}
	return parseConntrackLineWithSources(tenantID, line, sourceNetworks)
}

func parseConntrackLineWithSources(tenantID string, line string, sourceNetworks []*net.IPNet) (policy.Request, bool, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return policy.Request{}, false, nil
	}

	var sourceIP net.IP
	var destIP net.IP
	for _, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, "[],")
		switch key {
		case "src":
			if sourceIP == nil {
				sourceIP = net.ParseIP(value)
			}
		case "dst":
			if destIP == nil {
				destIP = net.ParseIP(value)
			}
		}
		if sourceIP != nil && destIP != nil {
			break
		}
	}
	if sourceIP == nil || destIP == nil {
		return policy.Request{}, false, nil
	}
	if len(sourceNetworks) > 0 && !ipInAnyNetwork(sourceIP, sourceNetworks) {
		return policy.Request{}, false, nil
	}
	return policy.Request{
		TenantID: strings.TrimSpace(tenantID),
		IP:       destIP.String(),
	}, true, nil
}

func parsePacketObservationSourceNetworks(options PacketObservationOptions) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, raw := range options.SourceCIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid packet observation source cidr %q: %w", raw, err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func ipInAnyNetwork(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
