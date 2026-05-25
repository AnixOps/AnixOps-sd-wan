package edge

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestForwardBidirectionalCopiesBothDirections(t *testing.T) {
	clientApp, clientEdge := net.Pipe()
	egressEdge, egressApp := net.Pipe()
	defer clientApp.Close()
	defer egressApp.Close()
	setPipeDeadlines(t, clientApp, clientEdge, egressEdge, egressApp)

	done := make(chan struct {
		stats ForwardStats
		err   error
	}, 1)
	go func() {
		stats, err := ForwardBidirectional(context.Background(), clientEdge, egressEdge)
		done <- struct {
			stats ForwardStats
			err   error
		}{stats: stats, err: err}
	}()

	writeDone := startWrite(clientApp, []byte("hello egress"))
	if got := readExact(t, egressApp, len("hello egress")); !bytes.Equal(got, []byte("hello egress")) {
		t.Fatalf("unexpected client-to-egress payload %q", string(got))
	}
	awaitWrite(t, writeDone)

	writeDone = startWrite(egressApp, []byte("hello client"))
	if got := readExact(t, clientApp, len("hello client")); !bytes.Equal(got, []byte("hello client")) {
		t.Fatalf("unexpected egress-to-client payload %q", string(got))
	}
	awaitWrite(t, writeDone)

	_ = clientApp.Close()
	_ = egressApp.Close()
	result := <-done
	if result.err != nil {
		t.Fatalf("forward returned error: %v", result.err)
	}
	if result.stats.ClientToEgressBytes != int64(len("hello egress")) {
		t.Fatalf("unexpected client-to-egress bytes: %+v", result.stats)
	}
	if result.stats.EgressToClientBytes != int64(len("hello client")) {
		t.Fatalf("unexpected egress-to-client bytes: %+v", result.stats)
	}
}

func TestForwardBidirectionalRequiresConnections(t *testing.T) {
	if _, err := ForwardBidirectional(context.Background(), nil, nil); err == nil {
		t.Fatal("expected nil connections to be rejected")
	}
}

func setPipeDeadlines(t *testing.T, conns ...net.Conn) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for _, conn := range conns {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
	}
}

func startWrite(conn net.Conn, payload []byte) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		errCh <- err
	}()
	return errCh
}

func awaitWrite(t *testing.T, errCh <-chan error) {
	t.Helper()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("write payload: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out writing payload")
	}
}

func readExact(t *testing.T, conn net.Conn, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	return buf
}
