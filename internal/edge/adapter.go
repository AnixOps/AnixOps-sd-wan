package edge

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"anixops-sd-wan/internal/transport"
)

type IngressAdapter interface {
	Protocol() transport.Protocol
	Listen(context.Context) (ConnListener, TokenExtractor, error)
}

type StaticIngressAdapter struct {
	Proto     transport.Protocol
	Listener  ConnListener
	Extractor TokenExtractor
}

func (a StaticIngressAdapter) Protocol() transport.Protocol {
	return a.Proto
}

func (a StaticIngressAdapter) Listen(ctx context.Context) (ConnListener, TokenExtractor, error) {
	if err := validateIngressProtocol(a.Proto); err != nil {
		return nil, nil, err
	}
	if a.Listener == nil {
		return nil, nil, fmt.Errorf("ingress listener is required")
	}
	if a.Extractor == nil {
		return nil, nil, fmt.Errorf("token extractor is required")
	}
	return a.Listener, a.Extractor, nil
}

type TCPIngressAdapter struct {
	Proto        transport.Protocol
	Address      string
	ListenConfig *net.ListenConfig
	Extractor    TokenExtractor
}

func (a TCPIngressAdapter) Protocol() transport.Protocol {
	return a.Proto
}

func (a TCPIngressAdapter) Listen(ctx context.Context) (ConnListener, TokenExtractor, error) {
	if err := validateIngressProtocol(a.Proto); err != nil {
		return nil, nil, err
	}
	address := strings.TrimSpace(a.Address)
	if address == "" {
		return nil, nil, fmt.Errorf("ingress listen address is required")
	}
	if a.Extractor == nil {
		return nil, nil, fmt.Errorf("token extractor is required")
	}
	listenConfig := a.ListenConfig
	if listenConfig == nil {
		listenConfig = &net.ListenConfig{}
	}
	listener, err := listenConfig.Listen(ctx, "tcp", address)
	if err != nil {
		return nil, nil, err
	}
	return listener, a.Extractor, nil
}

func (r *IngressRuntime) ServeAdapter(ctx context.Context, adapter IngressAdapter) error {
	if adapter == nil {
		return fmt.Errorf("ingress adapter is required")
	}
	listener, extractor, err := adapter.Listen(ctx)
	if err != nil {
		return err
	}
	return r.Serve(ctx, listener, extractor)
}

type LineTokenExtractor struct {
	Prefix      string
	MaxBytes    int
	ReadTimeout time.Duration
}

func (e LineTokenExtractor) ExtractToken(ctx context.Context, conn net.Conn) (string, error) {
	if conn == nil {
		return "", fmt.Errorf("connection is required")
	}
	maxBytes := e.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 4096
	}
	if e.ReadTimeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(e.ReadTimeout)); err != nil {
			return "", err
		}
		defer conn.SetReadDeadline(time.Time{})
	}

	line := make([]byte, 0, 64)
	buf := make([]byte, 1)
	for len(line) < maxBytes {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		n, err := conn.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				return extractLineToken(line, e.Prefix)
			}
			line = append(line, buf[0])
		}
		if err != nil {
			if err == io.EOF && len(line) > 0 {
				return extractLineToken(line, e.Prefix)
			}
			return "", err
		}
	}
	return "", fmt.Errorf("edge token line exceeds %d bytes", maxBytes)
}

func extractLineToken(line []byte, prefix string) (string, error) {
	raw := strings.TrimSpace(string(line))
	if prefix != "" {
		if !strings.HasPrefix(raw, prefix) {
			return "", fmt.Errorf("edge token line does not match expected prefix")
		}
		raw = strings.TrimSpace(strings.TrimPrefix(raw, prefix))
	}
	if raw == "" {
		return "", fmt.Errorf("edge token is required")
	}
	return raw, nil
}

func validateIngressProtocol(protocol transport.Protocol) error {
	if !transport.KnownProtocol(protocol) {
		return fmt.Errorf("unknown ingress protocol %q", protocol)
	}
	return nil
}
