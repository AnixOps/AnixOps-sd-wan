package edge

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestIngressRuntimeLiveForwardingAndFailover(t *testing.T) {
	if os.Getenv("ANIXOPS_REQUIRE_EDGE_RUNTIME") != "1" {
		t.Skip("edge runtime verification is only required in the remote runtime gate")
	}

	ingressPort := freeTCPPort(t)
	healthyPort := freeTCPPort(t)
	deadPort := freeTCPPort(t)

	ingressListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ingressPort))
	if err != nil {
		t.Fatalf("listen ingress: %v", err)
	}
	t.Cleanup(func() { _ = ingressListener.Close() })

	egressListener, egressReceived, egressReply := startEchoEgressServer(t, healthyPort)
	t.Cleanup(func() { _ = egressListener.Close() })

	auth, err := NewAuthenticator([]Credential{{
		Token:    "token-a",
		TenantID: "tenant-a",
		DeviceID: "agent-a",
	}})
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	limiter, err := NewWindowLimiter(1, time.Minute)
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}
	tracker, err := NewHealthTracker(time.Minute)
	if err != nil {
		t.Fatalf("new tracker: %v", err)
	}
	now := time.Now().UTC()
	for _, heartbeat := range []Heartbeat{
		{ID: "edge-a", Region: "jp", Load: 20, Observed: now},
		{ID: "edge-b", Region: "hk", Load: 5, Observed: now},
	} {
		if err := tracker.Observe(heartbeat); err != nil {
			t.Fatalf("observe %s: %v", heartbeat.ID, err)
		}
	}
	resolver, err := NewStaticEgressResolver([]EgressTarget{
		{NodeID: "edge-a", Region: "jp", Address: fmt.Sprintf("127.0.0.1:%d", healthyPort)},
		{NodeID: "edge-b", Region: "hk", Address: fmt.Sprintf("127.0.0.1:%d", deadPort)},
	})
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	runtime, err := NewIngressRuntime(auth, limiter, tracker, NewScheduler(), resolver, EgressDialFunc(func(ctx context.Context, target EgressTarget) (net.Conn, error) {
		dialer := &net.Dialer{Timeout: 2 * time.Second}
		return dialer.DialContext(ctx, "tcp", target.Address)
	}))
	if err != nil {
		t.Fatalf("new ingress runtime: %v", err)
	}

	ctx := context.Background()

	client1, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", ingressPort), 2*time.Second)
	if err != nil {
		t.Fatalf("dial ingress: %v", err)
	}
	if _, err := io.WriteString(client1, "ANIXOPS token-a\nhello-edge\n"); err != nil {
		t.Fatalf("write client payload: %v", err)
	}
	firstConn, err := ingressListener.Accept()
	if err != nil {
		t.Fatalf("accept ingress: %v", err)
	}
	token, err := (LineTokenExtractor{Prefix: "ANIXOPS "}).ExtractToken(ctx, firstConn)
	if err != nil {
		t.Fatalf("extract token: %v", err)
	}
	firstDone := make(chan struct{})
	go func() {
		_, _ = runtime.HandleConnection(ctx, token, firstConn)
		close(firstDone)
	}()

	reply := bufio.NewReader(client1)
	line, err := reply.ReadString('\n')
	if err != nil {
		t.Fatalf("read forwarded reply: %v", err)
	}
	if strings.TrimSpace(line) != "echo:hello-edge" {
		t.Fatalf("expected forwarded reply, got %q", line)
	}
	_ = client1.Close()
	select {
	case <-firstDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for first connection to finish")
	}

	select {
	case msg := <-egressReceived:
		if strings.TrimSpace(msg) != "hello-edge" {
			t.Fatalf("expected real egress payload, got %q", msg)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for egress server payload")
	}
	select {
	case msg := <-egressReply:
		if strings.TrimSpace(msg) != "echo:hello-edge" {
			t.Fatalf("expected egress reply, got %q", msg)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for egress reply write")
	}

	client2, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", ingressPort), 2*time.Second)
	if err != nil {
		t.Fatalf("dial ingress second time: %v", err)
	}
	if _, err := io.WriteString(client2, "ANIXOPS token-a\nshould-block\n"); err != nil {
		t.Fatalf("write second client payload: %v", err)
	}
	secondConn, err := ingressListener.Accept()
	if err != nil {
		t.Fatalf("accept second ingress: %v", err)
	}
	secondToken, err := (LineTokenExtractor{Prefix: "ANIXOPS "}).ExtractToken(ctx, secondConn)
	if err != nil {
		t.Fatalf("extract second token: %v", err)
	}
	secondDone := make(chan struct{})
	go func() {
		_, _ = runtime.HandleConnection(ctx, secondToken, secondConn)
		close(secondDone)
	}()
	if err := client2.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := io.ReadAll(client2); err == nil {
		t.Fatal("expected second connection to be rate limited and closed")
	}
	_ = client2.Close()
	select {
	case <-secondDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for second connection to finish")
	}
}

func startEchoEgressServer(t *testing.T, port int) (net.Listener, chan string, chan string) {
	t.Helper()

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("listen egress: %v", err)
	}
	received := make(chan string, 1)
	replied := make(chan string, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				payload, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				msg := strings.TrimSpace(payload)
				received <- msg
				reply := "echo:" + msg + "\n"
				replied <- strings.TrimSpace(reply)
				_, _ = io.WriteString(c, reply)
			}(conn)
		}
	}()
	return ln, received, replied
}

func freeTCPPort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate tcp port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitForTCPPort(t *testing.T, address string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", address)
}
