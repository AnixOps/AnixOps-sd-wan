package edge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

type ForwardStats struct {
	ClientToEgressBytes int64 `json:"client_to_egress_bytes"`
	EgressToClientBytes int64 `json:"egress_to_client_bytes"`
}

type copyResult struct {
	direction string
	bytes     int64
	err       error
}

func ForwardBidirectional(ctx context.Context, client, egress net.Conn) (ForwardStats, error) {
	if client == nil {
		return ForwardStats{}, fmt.Errorf("client connection is required")
	}
	if egress == nil {
		return ForwardStats{}, fmt.Errorf("egress connection is required")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan copyResult, 2)
	go copyConnection(results, "client_to_egress", egress, client)
	go copyConnection(results, "egress_to_client", client, egress)
	go func() {
		<-ctx.Done()
		_ = client.Close()
		_ = egress.Close()
	}()

	var stats ForwardStats
	var firstErr error
	for i := 0; i < 2; i++ {
		result := <-results
		if i == 0 {
			_ = client.Close()
			_ = egress.Close()
		}
		switch result.direction {
		case "client_to_egress":
			stats.ClientToEgressBytes = result.bytes
		case "egress_to_client":
			stats.EgressToClientBytes = result.bytes
		}
		if result.err != nil && !expectedCloseError(result.err) && firstErr == nil {
			firstErr = result.err
		}
	}
	if firstErr != nil {
		return stats, firstErr
	}
	if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return stats, err
	}
	return stats, nil
}

func copyConnection(results chan<- copyResult, direction string, dst, src net.Conn) {
	n, err := io.Copy(dst, src)
	results <- copyResult{direction: direction, bytes: n, err: err}
}

func expectedCloseError(err error) bool {
	if err == nil {
		return true
	}
	return errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.ErrClosedPipe) ||
		strings.Contains(strings.ToLower(err.Error()), "closed pipe") ||
		strings.Contains(strings.ToLower(err.Error()), "use of closed network connection")
}
