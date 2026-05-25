package transport

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestWireGuardClientConfigRenderDeterministic(t *testing.T) {
	rendered, err := WireGuardClientConfig{
		PrivateKey: "client-private",
		Address:    "10.40.0.2/32",
		DNS:        []string{"8.8.8.8", "1.1.1.1"},
		MTU:        1420,
		Peer: WireGuardClientPeer{
			PublicKey:                  "edge-public",
			Endpoint:                   "edge.example.com:51820",
			AllowedIPs:                 []string{"::/0", "0.0.0.0/0"},
			PersistentKeepaliveSeconds: 25,
		},
	}.Render()
	if err != nil {
		t.Fatalf("render wireguard client config: %v", err)
	}

	want := `[Interface]
Address = 10.40.0.2/32
PrivateKey = client-private
DNS = 1.1.1.1, 8.8.8.8
MTU = 1420

[Peer]
PublicKey = edge-public
Endpoint = edge.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`
	if rendered != want {
		t.Fatalf("unexpected wireguard config:\n%s", rendered)
	}
}

func TestHysteria2ClientConfigRender(t *testing.T) {
	rendered, err := Hysteria2ClientConfig{
		Server:        "edge.example.com:443",
		Auth:          "shared-secret",
		ALPN:          []string{"h3-29", "h3"},
		PinSHA256:     "pin",
		ObfsPassword:  "obfs-secret",
		Socks5Listen:  "127.0.0.1:1080",
		HTTPListen:    "127.0.0.1:8080",
		BandwidthUp:   "100 mbps",
		BandwidthDown: "200 mbps",
	}.Render()
	if err != nil {
		t.Fatalf("render hysteria2 client config: %v", err)
	}

	for _, want := range []string{
		`server: "edge.example.com:443"`,
		`auth: "shared-secret"`,
		`  sni: "edge.example.com"`,
		`  insecure: false`,
		`  pinSHA256: "pin"`,
		`    - "h3"` + "\n" + `    - "h3-29"`,
		`  type: "salamander"`,
		`    password: "obfs-secret"`,
		`  up: "100 mbps"`,
		`  down: "200 mbps"`,
		`  listen: "127.0.0.1:1080"`,
		`  listen: "127.0.0.1:8080"`,
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("expected hysteria2 config to contain %q:\n%s", want, rendered)
		}
	}
}

func TestRealityClientConfigRenderXrayJSON(t *testing.T) {
	rendered, err := RealityClientConfig{
		Server:           "reality.example.com:443",
		UUID:             "00000000-0000-4000-8000-000000000001",
		ServerName:       "www.example.com",
		PublicKey:        "reality-public-key",
		ShortID:          "abcd",
		SpiderX:          "/cdn",
		Fingerprint:      "chrome",
		Flow:             "xtls-rprx-vision",
		LocalSocksListen: "127.0.0.1:1090",
	}.Render()
	if err != nil {
		t.Fatalf("render reality client config: %v", err)
	}
	rerendered, err := RealityClientConfig{
		Server:           "reality.example.com:443",
		UUID:             "00000000-0000-4000-8000-000000000001",
		ServerName:       "www.example.com",
		PublicKey:        "reality-public-key",
		ShortID:          "abcd",
		SpiderX:          "/cdn",
		Fingerprint:      "chrome",
		Flow:             "xtls-rprx-vision",
		LocalSocksListen: "127.0.0.1:1090",
	}.Render()
	if err != nil {
		t.Fatalf("rerender reality client config: %v", err)
	}
	if rendered != rerendered {
		t.Fatal("expected deterministic reality config rendering")
	}

	var parsed xrayClientConfig
	if err := json.Unmarshal([]byte(rendered), &parsed); err != nil {
		t.Fatalf("reality config should be valid json: %v\n%s", err, rendered)
	}
	if parsed.Inbounds[0].Listen != "127.0.0.1" || parsed.Inbounds[0].Port != 1090 {
		t.Fatalf("unexpected socks inbound: %+v", parsed.Inbounds[0])
	}
	outbound := parsed.Outbounds[0]
	if outbound.Protocol != "vless" || outbound.Settings.VNext[0].Address != "reality.example.com" || outbound.Settings.VNext[0].Port != 443 {
		t.Fatalf("unexpected vless outbound: %+v", outbound)
	}
	if outbound.StreamSettings.RealitySettings.PublicKey != "reality-public-key" || outbound.StreamSettings.RealitySettings.ShortID != "abcd" {
		t.Fatalf("unexpected reality settings: %+v", outbound.StreamSettings.RealitySettings)
	}
}

func TestTUICClientConfigRenderJSON(t *testing.T) {
	rendered, err := TUICClientConfig{
		Server:           "tuic.example.com:443",
		UUID:             "00000000-0000-4000-8000-000000000002",
		Password:         "tuic-secret",
		Certificates:     []string{"/etc/anixops/tuic.crt"},
		ALPN:             []string{"h3-29", "h3"},
		LocalSocksListen: "127.0.0.1:1081",
	}.Render()
	if err != nil {
		t.Fatalf("render tuic client config: %v", err)
	}
	var parsed tuicClientConfig
	if err := json.Unmarshal([]byte(rendered), &parsed); err != nil {
		t.Fatalf("tuic config should be valid json: %v\n%s", err, rendered)
	}
	if parsed.Relay.Server != "tuic.example.com:443" || parsed.Relay.IP != "tuic.example.com" {
		t.Fatalf("unexpected tuic relay config: %+v", parsed)
	}
	if parsed.Relay.CongestionControl != "bbr" || parsed.Relay.UDPRelayMode != "native" {
		t.Fatalf("unexpected tuic defaults: %+v", parsed)
	}
	if strings.Join(parsed.Relay.ALPN, ",") != "h3,h3-29" {
		t.Fatalf("expected sorted alpn, got %+v", parsed.Relay.ALPN)
	}
	if len(parsed.Relay.Certificates) != 1 || parsed.Relay.Certificates[0] != "/etc/anixops/tuic.crt" {
		t.Fatalf("unexpected tuic certs: %+v", parsed.Relay.Certificates)
	}
	if parsed.Local.Server != "127.0.0.1:1081" || parsed.Local.DualStack || parsed.Local.MaxPacketSize != 1500 {
		t.Fatalf("unexpected tuic local config: %+v", parsed.Local)
	}
	if parsed.LogLevel != "warn" {
		t.Fatalf("unexpected tuic log level: %+v", parsed.LogLevel)
	}
}

func TestClientConfigSetRenderAllMatchesLifecycleFilenames(t *testing.T) {
	configs := ClientConfigSet{
		WireGuard: &WireGuardClientConfig{
			PrivateKey: "client-private",
			Address:    "10.40.0.2/32",
			Peer: WireGuardClientPeer{
				PublicKey:  "edge-public",
				Endpoint:   "edge.example.com:51820",
				AllowedIPs: []string{"0.0.0.0/0"},
			},
		},
		Hysteria2: &Hysteria2ClientConfig{Server: "edge.example.com:443", Auth: "secret"},
		Reality:   &RealityClientConfig{Server: "reality.example.com:443", UUID: "uuid", PublicKey: "public-key"},
		TUIC:      &TUICClientConfig{Server: "tuic.example.com:443", UUID: "uuid", Password: "password", Certificates: []string{"/etc/anixops/tuic.crt"}},
	}
	rendered, err := configs.RenderAll()
	if err != nil {
		t.Fatalf("render config set: %v", err)
	}
	if len(rendered) != 4 {
		t.Fatalf("expected four rendered configs, got %+v", rendered)
	}

	seen := make(map[string]bool)
	for _, item := range rendered {
		if item.Perm != 0o600 {
			t.Fatalf("expected private config permissions, got %s for %s", item.Perm, item.FileName)
		}
		seen[item.FileName] = true
		path, err := ConfigPath("/tmp/anixops", item.Protocol)
		if err != nil {
			t.Fatalf("config path for %s: %v", item.Protocol, err)
		}
		if !strings.HasSuffix(path, item.FileName) {
			t.Fatalf("expected lifecycle path %q to end with %q", path, item.FileName)
		}
	}
	for _, spec := range DefaultLifecycleSpecs("/tmp/anixops") {
		name, err := ConfigFileName(spec.Protocol)
		if err != nil {
			t.Fatalf("config file name for %s: %v", spec.Protocol, err)
		}
		if !seen[name] {
			t.Fatalf("rendered configs missing lifecycle file %s", name)
		}
	}

	writer := newRecordingConfigWriter()
	if err := configs.WriteAll("/tmp/anixops", writer); err != nil {
		t.Fatalf("write config set: %v", err)
	}
	for _, item := range rendered {
		path, err := ConfigPath("/tmp/anixops", item.Protocol)
		if err != nil {
			t.Fatalf("config path for %s: %v", item.Protocol, err)
		}
		if string(writer.files[path]) != item.Content {
			t.Fatalf("expected written content for %s", path)
		}
		if writer.perms[path] != 0o600 {
			t.Fatalf("expected private file mode for %s, got %s", path, writer.perms[path])
		}
	}
}

func TestClientConfigValidationRejectsInvalidEndpoint(t *testing.T) {
	_, err := Hysteria2ClientConfig{
		Server: "edge.example.com",
		Auth:   "secret",
	}.Render()
	if err == nil {
		t.Fatal("expected invalid endpoint error")
	}
	if !strings.Contains(err.Error(), "missing port") {
		t.Fatalf("expected missing port error, got %v", err)
	}
}

type recordingConfigWriter struct {
	files map[string][]byte
	perms map[string]os.FileMode
}

func newRecordingConfigWriter() *recordingConfigWriter {
	return &recordingConfigWriter{
		files: make(map[string][]byte),
		perms: make(map[string]os.FileMode),
	}
}

func (w *recordingConfigWriter) WriteFile(path string, data []byte, perm os.FileMode) error {
	w.files[path] = append([]byte(nil), data...)
	w.perms[path] = perm
	return nil
}
