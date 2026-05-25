package edge

import (
	"context"
	"net"
	"testing"
	"time"

	"anixops-sd-wan/internal/transport"
)

func TestLineTokenExtractorLeavesPayloadForForwarder(t *testing.T) {
	clientApp, clientEdge := net.Pipe()
	defer clientApp.Close()
	defer clientEdge.Close()
	setPipeDeadlines(t, clientApp, clientEdge)

	writeDone := startWrite(clientApp, []byte("ANIXOPS token-a\npayload"))
	token, err := LineTokenExtractor{Prefix: "ANIXOPS "}.ExtractToken(context.Background(), clientEdge)
	if err != nil {
		t.Fatalf("extract token: %v", err)
	}
	if token != "token-a" {
		t.Fatalf("expected token-a, got %q", token)
	}
	if got := string(readExact(t, clientEdge, len("payload"))); got != "payload" {
		t.Fatalf("expected payload to remain readable, got %q", got)
	}
	awaitWrite(t, writeDone)
}

func TestLineTokenExtractorRejectsOversizedTokenLine(t *testing.T) {
	clientApp, clientEdge := net.Pipe()
	defer clientApp.Close()
	defer clientEdge.Close()
	setPipeDeadlines(t, clientApp, clientEdge)

	writeDone := startWrite(clientApp, []byte("ANIXOPS token-a\n"))
	_, err := LineTokenExtractor{Prefix: "ANIXOPS ", MaxBytes: 4}.ExtractToken(context.Background(), clientEdge)
	if err == nil {
		t.Fatal("expected oversized token line to be rejected")
	}
	_ = clientEdge.Close()
	<-writeDone
}

func TestIngressRuntimeServeAdapterForwardsLineAuthenticatedStream(t *testing.T) {
	clientApp, clientEdge := net.Pipe()
	egressEdge, egressApp := net.Pipe()
	defer clientApp.Close()
	defer egressApp.Close()
	setPipeDeadlines(t, clientApp, clientEdge, egressEdge, egressApp)

	runtime := newTestIngressRuntime(t, time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC), 2, &recordingEgressDialer{conn: egressEdge})
	adapter := StaticIngressAdapter{
		Proto:     transport.ProtocolHysteria2,
		Listener:  newScriptedListener(clientEdge),
		Extractor: LineTokenExtractor{Prefix: "ANIXOPS "},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runtime.ServeAdapter(ctx, adapter)
	}()

	writeDone := startWrite(clientApp, []byte("ANIXOPS token-a\nclient payload"))
	if got := string(readExact(t, egressApp, len("client payload"))); got != "client payload" {
		t.Fatalf("unexpected payload at egress: %q", got)
	}
	awaitWrite(t, writeDone)
	_ = clientApp.Close()
	_ = egressApp.Close()
	cancel()

	err := <-errCh
	if err != nil && err != context.Canceled {
		t.Fatalf("serve adapter returned unexpected error: %v", err)
	}
}

func TestIngressAdapterValidation(t *testing.T) {
	if _, _, err := (StaticIngressAdapter{
		Proto:     transport.Protocol("unknown"),
		Listener:  newScriptedListener(),
		Extractor: LineTokenExtractor{},
	}).Listen(context.Background()); err == nil {
		t.Fatal("expected unknown protocol to be rejected")
	}
	if _, _, err := (TCPIngressAdapter{
		Proto:     transport.ProtocolReality,
		Extractor: LineTokenExtractor{},
	}).Listen(context.Background()); err == nil {
		t.Fatal("expected missing listen address to be rejected")
	}
}
