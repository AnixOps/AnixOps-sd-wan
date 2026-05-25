package protocol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anixops-sd-wan/internal/transport"
	"golang.org/x/net/proxy"
)

func TestProtocolRuntimeInterop(t *testing.T) {
	if os.Getenv("ANIXOPS_REQUIRE_PROTOCOL_INTEROP") != "1" {
		t.Skip("protocol runtime interop is only required in the remote protocol test run")
	}

	requireBinary(t, "hysteria")
	requireBinary(t, "wg-quick")
	requireBinary(t, "xray")
	requireBinary(t, "tuic-client")
	requireBinary(t, "tuic-server")

	t.Run("hysteria2", func(t *testing.T) {
		runHysteria2Interop(t)
	})
	t.Run("wireguard", func(t *testing.T) {
		runWireGuardInterop(t)
	})
	t.Run("reality", func(t *testing.T) {
		runRealityInterop(t)
	})
	t.Run("tuic", func(t *testing.T) {
		runTUICInterop(t)
	})
}

func TestProtocolRuntimeSwitching(t *testing.T) {
	if os.Getenv("ANIXOPS_REQUIRE_PROTOCOL_INTEROP") != "1" {
		t.Skip("protocol runtime switching is only required in the remote protocol test run")
	}

	requireBinary(t, "hysteria")
	requireBinary(t, "xray")
	requireBinary(t, "tuic-client")
	requireBinary(t, "tuic-server")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("switch-ok"))
	}))
	t.Cleanup(target.Close)

	tempDir := t.TempDir()
	serverPorts := map[transport.Protocol]int{
		transport.ProtocolHysteria2: freeUDPPort(t),
		transport.ProtocolTUIC:      freeUDPPort(t),
	}
	clientPorts := map[transport.Protocol]int{
		transport.ProtocolHysteria2: freeTCPPort(t),
		transport.ProtocolTUIC:      freeTCPPort(t),
	}

	hysteriaCert, hysteriaKey := writeSelfSignedCert(t, []string{"127.0.0.1", "localhost"})
	tuicCert, tuicKey := writeSelfSignedCert(t, []string{"127.0.0.1", "localhost"})
	tuicUUID := randomUUID(t)

	writeText(t, filepath.Join(tempDir, "hysteria-server.yaml"), mustRender(t, transport.Hysteria2ServerConfig{
		Listen:       fmt.Sprintf("127.0.0.1:%d", serverPorts[transport.ProtocolHysteria2]),
		Auth:         "shared-secret",
		CertFile:     hysteriaCert,
		KeyFile:      hysteriaKey,
		ALPN:         []string{"h3"},
		ObfsPassword: "obfs-secret",
	}))
	writeText(t, filepath.Join(tempDir, "hysteria-client.yaml"), mustRender(t, transport.Hysteria2ClientConfig{
		Server:       fmt.Sprintf("127.0.0.1:%d", serverPorts[transport.ProtocolHysteria2]),
		Auth:         "shared-secret",
		Insecure:     true,
		ALPN:         []string{"h3"},
		ObfsPassword: "obfs-secret",
		Socks5Listen: fmt.Sprintf("127.0.0.1:%d", clientPorts[transport.ProtocolHysteria2]),
	}))
	writeText(t, filepath.Join(tempDir, "tuic-server.json"), mustRender(t, transport.TUICServerConfig{
		Listen:   fmt.Sprintf("127.0.0.1:%d", serverPorts[transport.ProtocolTUIC]),
		Users:    map[string]string{tuicUUID: "tuic-secret"},
		CertFile: tuicCert,
		KeyFile:  tuicKey,
		ALPN:     []string{"h3"},
	}))
	writeText(t, filepath.Join(tempDir, "tuic-client.json"), mustRender(t, transport.TUICClientConfig{
		Server:           fmt.Sprintf("127.0.0.1:%d", serverPorts[transport.ProtocolTUIC]),
		UUID:             tuicUUID,
		Password:         "tuic-secret",
		Certificates:     []string{tuicCert},
		ALPN:             []string{"h3"},
		LocalSocksListen: fmt.Sprintf("127.0.0.1:%d", clientPorts[transport.ProtocolTUIC]),
	}))

	startCommand(t, ctx, "hysteria", "server", "-c", filepath.Join(tempDir, "hysteria-server.yaml"))
	startCommand(t, ctx, "tuic-server", "-c", filepath.Join(tempDir, "tuic-server.json"))
	waitForUDPPort(t, fmt.Sprintf("127.0.0.1:%d", serverPorts[transport.ProtocolHysteria2]), 20*time.Second)
	waitForUDPPort(t, fmt.Sprintf("127.0.0.1:%d", serverPorts[transport.ProtocolTUIC]), 20*time.Second)
	startCommand(t, ctx, "hysteria", "client", "-c", filepath.Join(tempDir, "hysteria-client.yaml"))

	supervisor, err := transport.NewSupervisor(transport.ExecProcessStarter{}, nil, []transport.ProtocolLifecycleSpec{
		{
			Protocol: transport.ProtocolHysteria2,
			Mode:     transport.LifecycleProcess,
			Start:    transport.ProcessCommand{Name: "hysteria", Args: []string{"client", "-c", filepath.Join(tempDir, "hysteria-client.yaml")}},
		},
		{
			Protocol: transport.ProtocolTUIC,
			Mode:     transport.LifecycleProcess,
			Start:    transport.ProcessCommand{Name: "tuic-client", Args: []string{"-c", filepath.Join(tempDir, "tuic-client.json")}},
		},
	})
	if err != nil {
		t.Fatalf("new supervisor: %v", err)
	}
	runtime, err := transport.NewSwitchRuntime(transport.ProtocolHysteria2, 0, nil)
	if err != nil {
		t.Fatalf("new switch runtime: %v", err)
	}

	if _, err := runtime.Evaluate(ctx, time.Now().UTC(), transport.Signals{
		LinkClass:    transport.LinkPublic,
		UDPAvailable: true,
	}, supervisor.Activate); err != nil {
		t.Fatalf("evaluate hysteria2: %v", err)
	}
	waitForTCPPort(t, fmt.Sprintf("127.0.0.1:%d", clientPorts[transport.ProtocolHysteria2]), 20*time.Second)
	assertHTTPThroughSocks(t, fmt.Sprintf("127.0.0.1:%d", clientPorts[transport.ProtocolHysteria2]), target.URL, "switch-ok")

	if _, err := runtime.Evaluate(ctx, time.Now().UTC(), transport.Signals{
		LinkClass:    transport.LinkPublic,
		UDPAvailable: true,
		HandshakeSuccess: map[transport.Protocol]float64{
			transport.ProtocolHysteria2: 0.1,
			transport.ProtocolTUIC:      0.95,
		},
	}, supervisor.Activate); err != nil {
		t.Fatalf("evaluate tuic: %v", err)
	}
	waitForTCPPort(t, fmt.Sprintf("127.0.0.1:%d", clientPorts[transport.ProtocolTUIC]), 20*time.Second)
	assertHTTPThroughSocks(t, fmt.Sprintf("127.0.0.1:%d", clientPorts[transport.ProtocolTUIC]), target.URL, "switch-ok")
}

func runHysteria2Interop(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hysteria2-ok"))
	}))
	t.Cleanup(target.Close)

	certFile, keyFile := writeSelfSignedCert(t, []string{"127.0.0.1", "localhost"})
	serverPort := freeTCPPort(t)
	proxyPort := freeTCPPort(t)

	tempDir := t.TempDir()
	serverConfig := transport.Hysteria2ServerConfig{
		Listen:       fmt.Sprintf("127.0.0.1:%d", serverPort),
		Auth:         "shared-secret",
		CertFile:     certFile,
		KeyFile:      keyFile,
		ALPN:         []string{"h3"},
		ObfsPassword: "obfs-secret",
	}
	clientConfig := transport.Hysteria2ClientConfig{
		Server:       fmt.Sprintf("127.0.0.1:%d", serverPort),
		Auth:         "shared-secret",
		Insecure:     true,
		ALPN:         []string{"h3"},
		ObfsPassword: "obfs-secret",
		Socks5Listen: fmt.Sprintf("127.0.0.1:%d", proxyPort),
	}
	writeText(t, filepath.Join(tempDir, transport.Hysteria2ConfigFile), mustRender(t, serverConfig))
	writeText(t, filepath.Join(tempDir, "hysteria-client.yaml"), mustRender(t, clientConfig))

	startCommand(t, ctx, "hysteria", "server", "-c", filepath.Join(tempDir, transport.Hysteria2ConfigFile))
	startCommand(t, ctx, "hysteria", "client", "-c", filepath.Join(tempDir, "hysteria-client.yaml"))
	waitForTCPPort(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), 20*time.Second)
	assertHTTPThroughSocks(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), target.URL, "hysteria2-ok")
}

func runRealityInterop(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("reality-ok"))
	}))
	t.Cleanup(target.Close)

	dummyTLSAddr, stopDest := startTLSDestServer(t, []string{"localhost", "www.example.com"})
	t.Cleanup(stopDest)

	keyPair := generateXrayX25519(t)
	uuid := randomUUID(t)

	serverPort := freeTCPPort(t)
	proxyPort := freeTCPPort(t)
	tempDir := t.TempDir()

	serverConfig := transport.RealityServerConfig{
		Listen:      fmt.Sprintf("127.0.0.1:%d", serverPort),
		UUID:        uuid,
		PrivateKey:  keyPair.Private,
		Dest:        dummyTLSAddr,
		ServerNames: []string{"www.example.com"},
		ShortIDs:    []string{"abcd"},
		Flow:        "xtls-rprx-vision",
	}
	clientConfig := transport.RealityClientConfig{
		Server:           fmt.Sprintf("127.0.0.1:%d", serverPort),
		UUID:             uuid,
		ServerName:       "www.example.com",
		PublicKey:        keyPair.Public,
		ShortID:          "abcd",
		Flow:             "xtls-rprx-vision",
		LocalSocksListen: fmt.Sprintf("127.0.0.1:%d", proxyPort),
	}
	writeText(t, filepath.Join(tempDir, transport.RealityConfigFile), mustRender(t, serverConfig))
	writeText(t, filepath.Join(tempDir, "reality-client.json"), mustRender(t, clientConfig))

	startCommand(t, ctx, "xray", "run", "-config", filepath.Join(tempDir, transport.RealityConfigFile))
	waitForTCPPort(t, fmt.Sprintf("127.0.0.1:%d", serverPort), 20*time.Second)
	startCommand(t, ctx, "xray", "run", "-config", filepath.Join(tempDir, "reality-client.json"))
	waitForTCPPort(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), 20*time.Second)
	assertHTTPThroughSocks(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), target.URL, "reality-ok")
}

func runWireGuardInterop(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	leftKeys := generateWireGuardKeyPair(t)
	rightKeys := generateWireGuardKeyPair(t)
	leftPort := freeUDPPort(t)
	rightPort := freeUDPPort(t)
	tempDir := t.TempDir()

	leftConfig := transport.WireGuardClientConfig{
		PrivateKey: leftKeys.Private,
		Address:    "10.201.0.1/32",
		MTU:        1420,
		Peer: transport.WireGuardClientPeer{
			PublicKey:                  rightKeys.Public,
			Endpoint:                   fmt.Sprintf("127.0.0.1:%d", rightPort),
			AllowedIPs:                 []string{"10.201.0.2/32"},
			PersistentKeepaliveSeconds: 25,
		},
	}
	rightConfig := transport.WireGuardClientConfig{
		PrivateKey: rightKeys.Private,
		Address:    "10.201.0.2/32",
		MTU:        1420,
		Peer: transport.WireGuardClientPeer{
			PublicKey:                  leftKeys.Public,
			Endpoint:                   fmt.Sprintf("127.0.0.1:%d", leftPort),
			AllowedIPs:                 []string{"10.201.0.1/32"},
			PersistentKeepaliveSeconds: 25,
		},
	}
	leftPath := filepath.Join(tempDir, "wg-left.conf")
	rightPath := filepath.Join(tempDir, "wg-right.conf")
	writeText(t, leftPath, mustRender(t, leftConfig))
	writeText(t, rightPath, mustRender(t, rightConfig))

	runWGQuick(t, ctx, "up", rightPath)
	runWGQuick(t, ctx, "up", leftPath)
	t.Cleanup(func() {
		runWGQuickNoFail(t, "down", leftPath)
		runWGQuickNoFail(t, "down", rightPath)
	})

	listener, err := net.Listen("tcp", "10.201.0.2:0")
	if err != nil {
		t.Fatalf("wireguard target listener: %v", err)
	}
	defer listener.Close()

	var serveDone = make(chan struct{})
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("wireguard-ok"))
		}),
	}
	go func() {
		defer close(serveDone)
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Shutdown(context.Background())
		<-serveDone
	})

	assertHTTPDirect(t, fmt.Sprintf("http://10.201.0.2:%d", listener.Addr().(*net.TCPAddr).Port), "wireguard-ok")
}

func runTUICInterop(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tuic-ok"))
	}))
	t.Cleanup(target.Close)

	certFile, keyFile := writeSelfSignedCert(t, []string{"127.0.0.1", "localhost"})
	serverPort := freeUDPPort(t)
	proxyPort := freeTCPPort(t)
	tempDir := t.TempDir()
	userID := randomUUID(t)

	serverConfig := transport.TUICServerConfig{
		Listen:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		Users:             map[string]string{userID: "tuic-secret"},
		CertFile:          certFile,
		KeyFile:           keyFile,
		ALPN:              []string{"h3"},
		CongestionControl: "bbr",
		UDPRelayMode:      "native",
		ZeroRTTHandshake:  true,
	}
	clientConfig := transport.TUICClientConfig{
		Server:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		UUID:              userID,
		Password:          "tuic-secret",
		Certificates:      []string{certFile},
		ALPN:              []string{"h3"},
		CongestionControl: "bbr",
		LocalSocksListen:  fmt.Sprintf("127.0.0.1:%d", proxyPort),
	}
	writeText(t, filepath.Join(tempDir, transport.TUICConfigFile), mustRender(t, serverConfig))
	writeText(t, filepath.Join(tempDir, "tuic-client.json"), mustRender(t, clientConfig))

	startCommand(t, ctx, "tuic-server", "-c", filepath.Join(tempDir, transport.TUICConfigFile))
	startCommand(t, ctx, "tuic-client", "-c", filepath.Join(tempDir, "tuic-client.json"))
	waitForTCPPort(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), 20*time.Second)
	assertHTTPThroughSocks(t, fmt.Sprintf("127.0.0.1:%d", proxyPort), target.URL, "tuic-ok")
}

type x25519KeyPair struct {
	Private string
	Public  string
}

func generateXrayX25519(t *testing.T) x25519KeyPair {
	t.Helper()

	cmd := exec.Command("xray", "x25519")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("xray x25519: %v\n%s", err, output)
	}
	var pair x25519KeyPair
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "PrivateKey:"):
			pair.Private = strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey:"))
		case strings.HasPrefix(line, "Password (PublicKey):"):
			pair.Public = strings.TrimSpace(strings.TrimPrefix(line, "Password (PublicKey):"))
		}
	}
	if pair.Private == "" || pair.Public == "" {
		t.Fatalf("failed to parse xray x25519 output:\n%s", output)
	}
	return pair
}

type wireGuardKeyPair struct {
	Private string
	Public  string
}

func generateWireGuardKeyPair(t *testing.T) wireGuardKeyPair {
	t.Helper()

	privOutput, err := exec.Command("wg", "genkey").CombinedOutput()
	if err != nil {
		t.Fatalf("wg genkey: %v\n%s", err, privOutput)
	}
	private := strings.TrimSpace(string(privOutput))
	pubCmd := exec.Command("wg", "pubkey")
	pubCmd.Stdin = strings.NewReader(private)
	pubOutput, err := pubCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("wg pubkey: %v\n%s", err, pubOutput)
	}
	return wireGuardKeyPair{
		Private: private,
		Public:  strings.TrimSpace(string(pubOutput)),
	}
}

func startTLSDestServer(t *testing.T, dnsNames []string) (string, func()) {
	t.Helper()

	certFile, keyFile := writeSelfSignedCert(t, dnsNames)
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load tls key pair: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("start tls dest server: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Read(make([]byte, 1))
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

func assertHTTPThroughSocks(t *testing.T, socksAddr, targetURL, want string) {
	t.Helper()

	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatalf("create socks dialer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if cd, ok := dialer.(proxy.ContextDialer); ok {
				return cd.DialContext(ctx, network, addr)
			}
			return dialer.Dial(network, addr)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second}

	var lastErr error
	for i := 0; i < 80; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		resp, err := client.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				t.Fatalf("read response: %v", readErr)
			}
			if strings.Contains(string(body), want) {
				return
			}
			t.Fatalf("unexpected response body %q, want %q", body, want)
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("proxy request never succeeded: %v", lastErr)
}

func assertHTTPDirect(t *testing.T, targetURL, want string) {
	t.Helper()

	client := &http.Client{Timeout: 10 * time.Second}
	var lastErr error
	for i := 0; i < 20; i++ {
		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		resp, err := client.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				t.Fatalf("read response: %v", readErr)
			}
			if strings.Contains(string(body), want) {
				return
			}
			t.Fatalf("unexpected response body %q, want %q", body, want)
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("direct request never succeeded: %v", lastErr)
}

func startCommand(t *testing.T, ctx context.Context, name string, args ...string) *exec.Cmd {
	t.Helper()

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v\nstdout:\n%s\nstderr:\n%s", name, err, stdout.String(), stderr.String())
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("%s stdout:\n%s", name, stdout.String())
			t.Logf("%s stderr:\n%s", name, stderr.String())
		}
	})
	return cmd
}

func runWGQuick(t *testing.T, ctx context.Context, args ...string) {
	t.Helper()

	cmd := exec.CommandContext(ctx, "wg-quick", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("wg-quick %s: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func runWGQuickNoFail(t *testing.T, args ...string) {
	t.Helper()

	cmd := exec.Command("wg-quick", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("wg-quick %s failed during cleanup: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func waitForTCPPort(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for tcp listener %s", addr)
}

func waitForUDPPort(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("udp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for udp listener %s", addr)
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

func freeUDPPort(t *testing.T) int {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate udp port: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func writeSelfSignedCert(t *testing.T, dnsNames []string) (string, string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate tls key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "anixops-protocol-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, name := range dnsNames {
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		_ = certOut.Close()
		t.Fatalf("write cert file: %v", err)
	}
	if err := certOut.Close(); err != nil {
		t.Fatalf("close cert file: %v", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal tls key: %v", err)
	}
	keyOut, err := os.Create(keyFile)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		_ = keyOut.Close()
		t.Fatalf("write key file: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		t.Fatalf("close key file: %v", err)
	}
	return certFile, keyFile
}

func randomUUID(t *testing.T) string {
	t.Helper()

	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("generate uuid: %v", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func writeText(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func mustRender[T interface{ Render() (string, error) }](t *testing.T, cfg T) string {
	t.Helper()

	rendered, err := cfg.Render()
	if err != nil {
		t.Fatalf("render config: %v", err)
	}
	return rendered
}

func requireBinary(t *testing.T, name string) {
	t.Helper()

	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("missing required binary %s: %v", name, err)
	}
}
