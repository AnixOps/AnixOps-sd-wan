package edge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func TestIngressRuntimeSchedulesDialsAndForwardsConnection(t *testing.T) {
	clientApp, clientEdge := net.Pipe()
	egressEdge, egressApp := net.Pipe()
	defer clientApp.Close()
	defer egressApp.Close()
	setPipeDeadlines(t, clientApp, clientEdge, egressEdge, egressApp)

	dialer := &recordingEgressDialer{conn: egressEdge}
	runtime := newTestIngressRuntime(t, time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC), 2, dialer)

	done := make(chan struct {
		result IngressForwardResult
		err    error
	}, 1)
	go func() {
		result, err := runtime.HandleConnection(context.Background(), "token-a", clientEdge)
		done <- struct {
			result IngressForwardResult
			err    error
		}{result: result, err: err}
	}()

	writeDone := startWrite(clientApp, []byte("client payload"))
	if got := string(readExact(t, egressApp, len("client payload"))); got != "client payload" {
		t.Fatalf("unexpected payload at egress: %q", got)
	}
	awaitWrite(t, writeDone)

	writeDone = startWrite(egressApp, []byte("egress payload"))
	if got := string(readExact(t, clientApp, len("egress payload"))); got != "egress payload" {
		t.Fatalf("unexpected payload at client: %q", got)
	}
	awaitWrite(t, writeDone)

	_ = clientApp.Close()
	_ = egressApp.Close()
	outcome := <-done
	if outcome.err != nil {
		t.Fatalf("handle connection: %v", outcome.err)
	}
	if outcome.result.Assignment.EgressNodeID != "egress-b" {
		t.Fatalf("expected egress-b assignment, got %+v", outcome.result.Assignment)
	}
	if outcome.result.Target.Address != "10.0.0.2:443" {
		t.Fatalf("unexpected target: %+v", outcome.result.Target)
	}
	if outcome.result.Stats.ClientToEgressBytes != int64(len("client payload")) {
		t.Fatalf("unexpected forwarding stats: %+v", outcome.result.Stats)
	}
	targets := dialer.Targets()
	if len(targets) != 1 || targets[0].NodeID != "egress-b" {
		t.Fatalf("expected dial to selected egress-b, got %+v", targets)
	}
}

func TestIngressRuntimeFailsOverWhenLowestLoadEgressDialFails(t *testing.T) {
	clientApp, clientEdge := net.Pipe()
	egressEdge, egressApp := net.Pipe()
	defer clientApp.Close()
	defer egressApp.Close()
	setPipeDeadlines(t, clientApp, clientEdge, egressEdge, egressApp)

	dialer := &targetedEgressDialer{
		conns: map[string]net.Conn{
			"egress-a": egressEdge,
		},
		errs: map[string]error{
			"egress-b": fmt.Errorf("connection refused"),
		},
	}
	runtime := newTestIngressRuntime(t, time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC), 2, dialer)

	done := make(chan struct {
		result IngressForwardResult
		err    error
	}, 1)
	go func() {
		result, err := runtime.HandleConnection(context.Background(), "token-a", clientEdge)
		done <- struct {
			result IngressForwardResult
			err    error
		}{result: result, err: err}
	}()

	writeDone := startWrite(clientApp, []byte("failover payload"))
	if got := string(readExact(t, egressApp, len("failover payload"))); got != "failover payload" {
		t.Fatalf("unexpected failover payload at egress: %q", got)
	}
	awaitWrite(t, writeDone)

	_ = clientApp.Close()
	_ = egressApp.Close()
	outcome := <-done
	if outcome.err != nil {
		t.Fatalf("handle failover connection: %v", outcome.err)
	}
	if outcome.result.Assignment.EgressNodeID != "egress-a" {
		t.Fatalf("expected failover assignment to egress-a, got %+v", outcome.result.Assignment)
	}
	targets := dialer.Targets()
	if len(targets) != 2 || targets[0].NodeID != "egress-b" || targets[1].NodeID != "egress-a" {
		t.Fatalf("expected dial attempts egress-b then egress-a, got %+v", targets)
	}
}

func TestIngressRuntimeRejectsInvalidTokenBeforeDial(t *testing.T) {
	clientApp, clientEdge := net.Pipe()
	defer clientApp.Close()
	setPipeDeadlines(t, clientApp, clientEdge)

	dialer := &recordingEgressDialer{}
	runtime := newTestIngressRuntime(t, time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC), 2, dialer)

	if _, err := runtime.HandleConnection(context.Background(), "bad-token", clientEdge); err == nil {
		t.Fatal("expected invalid token error")
	}
	if targets := dialer.Targets(); len(targets) != 0 {
		t.Fatalf("invalid credentials should not dial egress, got %+v", targets)
	}
}

func TestIngressRuntimeServeAcceptsConnections(t *testing.T) {
	clientApp, clientEdge := net.Pipe()
	egressEdge, egressApp := net.Pipe()
	defer clientApp.Close()
	defer egressApp.Close()
	setPipeDeadlines(t, clientApp, clientEdge, egressEdge, egressApp)

	dialer := &recordingEgressDialer{conn: egressEdge}
	runtime := newTestIngressRuntime(t, time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC), 2, dialer)
	listener := newScriptedListener(clientEdge)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runtime.Serve(ctx, listener, TokenExtractorFunc(func(ctx context.Context, conn net.Conn) (string, error) {
			return "token-a", nil
		}))
	}()

	writeDone := startWrite(clientApp, []byte("served payload"))
	if got := string(readExact(t, egressApp, len("served payload"))); got != "served payload" {
		t.Fatalf("unexpected served payload: %q", got)
	}
	awaitWrite(t, writeDone)
	_ = clientApp.Close()
	_ = egressApp.Close()
	cancel()

	err := <-errCh
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("serve returned unexpected error: %v", err)
	}
	targets := dialer.Targets()
	if len(targets) != 1 || targets[0].NodeID != "egress-b" {
		t.Fatalf("expected listener path to dial egress-b, got %+v", targets)
	}
}

func newTestIngressRuntime(t *testing.T, now time.Time, limit int, dialer EgressDialer) *IngressRuntime {
	t.Helper()

	auth, err := NewAuthenticator([]Credential{{Token: "token-a", TenantID: "tenant-a", DeviceID: "agent-a"}})
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	limiter, err := NewWindowLimiter(limit, time.Minute)
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}
	tracker, err := NewHealthTracker(time.Minute)
	if err != nil {
		t.Fatalf("new tracker: %v", err)
	}
	if err := tracker.Observe(Heartbeat{ID: "egress-a", Region: "hk", Load: 20, Observed: now}); err != nil {
		t.Fatalf("observe egress-a: %v", err)
	}
	if err := tracker.Observe(Heartbeat{ID: "egress-b", Region: "jp", Load: 5, Observed: now}); err != nil {
		t.Fatalf("observe egress-b: %v", err)
	}
	resolver, err := NewStaticEgressResolver([]EgressTarget{
		{NodeID: "egress-a", Region: "hk", Address: "10.0.0.1:443"},
		{NodeID: "egress-b", Region: "jp", Address: "10.0.0.2:443"},
	})
	if err != nil {
		t.Fatalf("new egress resolver: %v", err)
	}
	runtime, err := NewIngressRuntime(auth, limiter, tracker, NewScheduler(), resolver, dialer)
	if err != nil {
		t.Fatalf("new ingress runtime: %v", err)
	}
	runtime.now = func() time.Time { return now }
	return runtime
}

type recordingEgressDialer struct {
	mu      sync.Mutex
	conn    net.Conn
	targets []EgressTarget
	err     error
}

func (d *recordingEgressDialer) DialEgress(ctx context.Context, target EgressTarget) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.targets = append(d.targets, target)
	if d.err != nil {
		return nil, d.err
	}
	if d.conn == nil {
		return nil, fmt.Errorf("egress connection is not configured")
	}
	return d.conn, nil
}

func (d *recordingEgressDialer) Targets() []EgressTarget {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]EgressTarget(nil), d.targets...)
}

type targetedEgressDialer struct {
	mu      sync.Mutex
	conns   map[string]net.Conn
	errs    map[string]error
	targets []EgressTarget
}

func (d *targetedEgressDialer) DialEgress(ctx context.Context, target EgressTarget) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.targets = append(d.targets, target)
	if err := d.errs[target.NodeID]; err != nil {
		return nil, err
	}
	conn := d.conns[target.NodeID]
	if conn == nil {
		return nil, fmt.Errorf("egress connection for %s is not configured", target.NodeID)
	}
	return conn, nil
}

func (d *targetedEgressDialer) Targets() []EgressTarget {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]EgressTarget(nil), d.targets...)
}

type scriptedListener struct {
	conns    chan net.Conn
	closed   chan struct{}
	closeOne sync.Once
}

func newScriptedListener(conns ...net.Conn) *scriptedListener {
	listener := &scriptedListener{
		conns:  make(chan net.Conn, len(conns)),
		closed: make(chan struct{}),
	}
	for _, conn := range conns {
		listener.conns <- conn
	}
	return listener
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *scriptedListener) Close() error {
	l.closeOne.Do(func() { close(l.closed) })
	return nil
}

func (l *scriptedListener) Addr() net.Addr {
	return staticAddr("scripted-listener")
}

type staticAddr string

func (a staticAddr) Network() string { return "tcp" }

func (a staticAddr) String() string { return string(a) }
