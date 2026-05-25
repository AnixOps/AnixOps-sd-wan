package transport

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHysteria2ServerConfigRender(t *testing.T) {
	config := Hysteria2ServerConfig{
		Listen:                "0.0.0.0:443",
		Auth:                  "shared-secret",
		CertFile:              "/etc/anixops/tls.crt",
		KeyFile:               "/etc/anixops/tls.key",
		ALPN:                  []string{"h3-29", "h3"},
		ObfsPassword:          "obfs-secret",
		BandwidthUp:           "1 gbps",
		BandwidthDown:         "2 gbps",
		MasqueradeURL:         "https://www.example.com/",
		MasqueradeRewriteHost: true,
	}
	rendered, err := config.Render()
	if err != nil {
		t.Fatalf("render hysteria2 server config: %v", err)
	}
	rerendered, err := config.Render()
	if err != nil {
		t.Fatalf("rerender hysteria2 server config: %v", err)
	}
	if rendered != rerendered {
		t.Fatal("expected deterministic hysteria2 server config rendering")
	}

	for _, want := range []string{
		`listen: "0.0.0.0:443"`,
		`  cert: "/etc/anixops/tls.crt"`,
		`  key: "/etc/anixops/tls.key"`,
		`    - "h3"` + "\n" + `    - "h3-29"`,
		`  type: "password"`,
		`  password: "shared-secret"`,
		`  type: "salamander"`,
		`    password: "obfs-secret"`,
		`  up: "1 gbps"`,
		`  down: "2 gbps"`,
		`    url: "https://www.example.com/"`,
		`    rewriteHost: true`,
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("expected hysteria2 server config to contain %q:\n%s", want, rendered)
		}
	}
}

func TestRealityServerConfigRenderXrayJSON(t *testing.T) {
	config := RealityServerConfig{
		Listen:      "0.0.0.0:443",
		UUID:        "00000000-0000-4000-8000-000000000003",
		PrivateKey:  "reality-private-key",
		Dest:        "www.example.com:443",
		ServerNames: []string{"b.example.com", "a.example.com"},
		ShortIDs:    []string{"ef01", "abcd"},
		Flow:        "xtls-rprx-vision",
	}
	rendered, err := config.Render()
	if err != nil {
		t.Fatalf("render reality server config: %v", err)
	}
	rerendered, err := config.Render()
	if err != nil {
		t.Fatalf("rerender reality server config: %v", err)
	}
	if rendered != rerendered {
		t.Fatal("expected deterministic reality server config rendering")
	}

	var parsed xrayServerConfig
	if err := json.Unmarshal([]byte(rendered), &parsed); err != nil {
		t.Fatalf("reality server config should be valid json: %v\n%s", err, rendered)
	}
	inbound := parsed.Inbounds[0]
	if inbound.Listen != "0.0.0.0" || inbound.Port != 443 || inbound.Protocol != "vless" {
		t.Fatalf("unexpected reality inbound: %+v", inbound)
	}
	if inbound.Settings.Decryption != "none" || inbound.Settings.Clients[0].ID != config.UUID || inbound.Settings.Clients[0].Flow != config.Flow {
		t.Fatalf("unexpected vless inbound settings: %+v", inbound.Settings)
	}
	settings := inbound.StreamSettings.RealitySettings
	if settings.PrivateKey != config.PrivateKey || settings.Dest != config.Dest {
		t.Fatalf("unexpected reality settings: %+v", settings)
	}
	if strings.Join(settings.ServerNames, ",") != "a.example.com,b.example.com" {
		t.Fatalf("expected sorted server names, got %+v", settings.ServerNames)
	}
	if strings.Join(settings.ShortIDs, ",") != "abcd,ef01" {
		t.Fatalf("expected sorted short ids, got %+v", settings.ShortIDs)
	}
	if parsed.Outbounds[0].Protocol != "freedom" {
		t.Fatalf("unexpected reality outbound: %+v", parsed.Outbounds[0])
	}
}

func TestTUICServerConfigRenderJSON(t *testing.T) {
	config := TUICServerConfig{
		Listen:   "0.0.0.0:443",
		Users:    map[string]string{"00000000-0000-4000-8000-000000000004": "secret"},
		CertFile: "/etc/anixops/tuic.crt",
		KeyFile:  "/etc/anixops/tuic.key",
		ALPN:     []string{"h3-29", "h3"},
	}
	rendered, err := config.Render()
	if err != nil {
		t.Fatalf("render tuic server config: %v", err)
	}
	rerendered, err := config.Render()
	if err != nil {
		t.Fatalf("rerender tuic server config: %v", err)
	}
	if rendered != rerendered {
		t.Fatal("expected deterministic tuic server config rendering")
	}

	var parsed tuicServerConfig
	if err := json.Unmarshal([]byte(rendered), &parsed); err != nil {
		t.Fatalf("tuic server config should be valid json: %v\n%s", err, rendered)
	}
	if parsed.Server != config.Listen || parsed.Certificate != config.CertFile || parsed.PrivateKey != config.KeyFile {
		t.Fatalf("unexpected tuic server tls config: %+v", parsed)
	}
	if parsed.Users["00000000-0000-4000-8000-000000000004"] != "secret" {
		t.Fatalf("unexpected tuic users: %+v", parsed.Users)
	}
	if parsed.CongestionControl != "bbr" || parsed.LogLevel != "warn" {
		t.Fatalf("unexpected tuic defaults: %+v", parsed)
	}
	if strings.Join(parsed.ALPN, ",") != "h3,h3-29" {
		t.Fatalf("expected sorted alpn, got %+v", parsed.ALPN)
	}
}

func TestServerConfigSetRenderAllAndWriteAll(t *testing.T) {
	configs := ServerConfigSet{
		Hysteria2: &Hysteria2ServerConfig{
			Listen:   "0.0.0.0:443",
			Auth:     "secret",
			CertFile: "/etc/anixops/hysteria.crt",
			KeyFile:  "/etc/anixops/hysteria.key",
		},
		Reality: &RealityServerConfig{
			Listen:     "0.0.0.0:8443",
			UUID:       "00000000-0000-4000-8000-000000000005",
			PrivateKey: "reality-private-key",
			Dest:       "www.example.com:443",
		},
		TUIC: &TUICServerConfig{
			Listen:   "0.0.0.0:9443",
			Users:    map[string]string{"00000000-0000-4000-8000-000000000006": "password"},
			CertFile: "/etc/anixops/tuic.crt",
			KeyFile:  "/etc/anixops/tuic.key",
		},
	}
	rendered, err := configs.RenderAll()
	if err != nil {
		t.Fatalf("render server config set: %v", err)
	}
	if len(rendered) != 3 {
		t.Fatalf("expected three rendered server configs, got %+v", rendered)
	}

	writer := newRecordingConfigWriter()
	if err := configs.WriteAll("/tmp/anixops-server", writer); err != nil {
		t.Fatalf("write server config set: %v", err)
	}
	for _, item := range rendered {
		if item.Perm != 0o600 {
			t.Fatalf("expected private config permissions, got %s for %s", item.Perm, item.FileName)
		}
		path, err := ServerConfigPath("/tmp/anixops-server", item.Protocol)
		if err != nil {
			t.Fatalf("server config path for %s: %v", item.Protocol, err)
		}
		if !strings.HasSuffix(path, item.FileName) {
			t.Fatalf("expected server config path %q to end with %q", path, item.FileName)
		}
		if string(writer.files[path]) != item.Content {
			t.Fatalf("expected written server config content for %s", path)
		}
		if writer.perms[path] != 0o600 {
			t.Fatalf("expected private file mode for %s, got %s", path, writer.perms[path])
		}
	}
}

func TestServerConfigValidationRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name string
		err  string
		run  func() error
	}{
		{
			name: "hysteria invalid listen",
			err:  "missing port",
			run: func() error {
				_, err := Hysteria2ServerConfig{
					Listen:   "0.0.0.0",
					Auth:     "secret",
					CertFile: "cert.pem",
					KeyFile:  "key.pem",
				}.Render()
				return err
			},
		},
		{
			name: "hysteria missing tls cert",
			err:  "tls cert file is required",
			run: func() error {
				_, err := Hysteria2ServerConfig{
					Listen:  "0.0.0.0:443",
					Auth:    "secret",
					KeyFile: "key.pem",
				}.Render()
				return err
			},
		},
		{
			name: "reality missing private key",
			err:  "private key is required",
			run: func() error {
				_, err := RealityServerConfig{
					Listen: "0.0.0.0:443",
					UUID:   "uuid",
					Dest:   "www.example.com:443",
				}.Render()
				return err
			},
		},
		{
			name: "tuic missing users",
			err:  "users are required",
			run: func() error {
				_, err := TUICServerConfig{
					Listen:   "0.0.0.0:443",
					CertFile: "cert.pem",
					KeyFile:  "key.pem",
				}.Render()
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.err) {
				t.Fatalf("expected error containing %q, got %v", tt.err, err)
			}
		})
	}
}
