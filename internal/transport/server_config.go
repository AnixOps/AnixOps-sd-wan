package transport

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

type RenderedServerConfig struct {
	Protocol Protocol
	FileName string
	Content  string
	Perm     os.FileMode
}

type ServerConfigWriter interface {
	WriteFile(path string, data []byte, perm os.FileMode) error
}

type ServerConfigSet struct {
	Hysteria2 *Hysteria2ServerConfig
	Reality   *RealityServerConfig
	TUIC      *TUICServerConfig
}

type Hysteria2ServerConfig struct {
	Listen                string
	Auth                  string
	CertFile              string
	KeyFile               string
	ALPN                  []string
	ObfsPassword          string
	BandwidthUp           string
	BandwidthDown         string
	MasqueradeURL         string
	MasqueradeRewriteHost bool
}

type RealityServerConfig struct {
	Listen      string
	UUID        string
	PrivateKey  string
	Dest        string
	ServerNames []string
	ShortIDs    []string
	Flow        string
}

type TUICServerConfig struct {
	Listen            string
	Users             map[string]string
	CertFile          string
	KeyFile           string
	ALPN              []string
	CongestionControl string
	UDPRelayMode      string
	ZeroRTTHandshake  bool
}

func ServerConfigFileName(protocol Protocol) (string, error) {
	return ConfigFileName(protocol)
}

func ServerConfigPath(configDir string, protocol Protocol) (string, error) {
	return ConfigPath(configDir, protocol)
}

func (s ServerConfigSet) RenderAll() ([]RenderedServerConfig, error) {
	var rendered []RenderedServerConfig
	if s.Hysteria2 != nil {
		content, err := s.Hysteria2.Render()
		if err != nil {
			return nil, err
		}
		rendered = append(rendered, RenderedServerConfig{
			Protocol: ProtocolHysteria2,
			FileName: Hysteria2ConfigFile,
			Content:  content,
			Perm:     0o600,
		})
	}
	if s.Reality != nil {
		content, err := s.Reality.Render()
		if err != nil {
			return nil, err
		}
		rendered = append(rendered, RenderedServerConfig{
			Protocol: ProtocolReality,
			FileName: RealityConfigFile,
			Content:  content,
			Perm:     0o600,
		})
	}
	if s.TUIC != nil {
		content, err := s.TUIC.Render()
		if err != nil {
			return nil, err
		}
		rendered = append(rendered, RenderedServerConfig{
			Protocol: ProtocolTUIC,
			FileName: TUICConfigFile,
			Content:  content,
			Perm:     0o600,
		})
	}
	if len(rendered) == 0 {
		return nil, fmt.Errorf("at least one server transport config is required")
	}
	return rendered, nil
}

func (s ServerConfigSet) WriteAll(configDir string, writer ServerConfigWriter) error {
	if writer == nil {
		return fmt.Errorf("server config writer is required")
	}
	rendered, err := s.RenderAll()
	if err != nil {
		return err
	}
	for _, item := range rendered {
		path, err := ServerConfigPath(configDir, item.Protocol)
		if err != nil {
			return err
		}
		if err := writer.WriteFile(path, []byte(item.Content), item.Perm); err != nil {
			return fmt.Errorf("write %s server config: %w", item.Protocol, err)
		}
	}
	return nil
}

func (c Hysteria2ServerConfig) Validate() error {
	if _, _, err := splitEndpoint(c.Listen); err != nil {
		return fmt.Errorf("invalid hysteria2 listen: %w", err)
	}
	if strings.TrimSpace(c.Auth) == "" {
		return fmt.Errorf("hysteria2 auth is required")
	}
	if strings.TrimSpace(c.CertFile) == "" {
		return fmt.Errorf("hysteria2 tls cert file is required")
	}
	if strings.TrimSpace(c.KeyFile) == "" {
		return fmt.Errorf("hysteria2 tls key file is required")
	}
	if len(c.ALPN) > 0 {
		if err := validateStringList("hysteria2 alpn", c.ALPN); err != nil {
			return err
		}
	}
	if c.MasqueradeURL != "" {
		parsed, err := url.Parse(c.MasqueradeURL)
		if err != nil {
			return fmt.Errorf("invalid hysteria2 masquerade url: %w", err)
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("invalid hysteria2 masquerade url: scheme and host are required")
		}
	}
	return nil
}

func (c Hysteria2ServerConfig) Render() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "listen: %s\n", yamlString(c.Listen))
	fmt.Fprintf(&b, "tls:\n")
	fmt.Fprintf(&b, "  cert: %s\n", yamlString(c.CertFile))
	fmt.Fprintf(&b, "  key: %s\n", yamlString(c.KeyFile))
	if len(c.ALPN) > 0 {
		fmt.Fprintf(&b, "  alpn:\n")
		for _, value := range sortedStrings(c.ALPN) {
			fmt.Fprintf(&b, "    - %s\n", yamlString(value))
		}
	}
	fmt.Fprintf(&b, "auth:\n")
	fmt.Fprintf(&b, "  type: %s\n", yamlString("password"))
	fmt.Fprintf(&b, "  password: %s\n", yamlString(c.Auth))
	if c.ObfsPassword != "" {
		fmt.Fprintf(&b, "obfs:\n")
		fmt.Fprintf(&b, "  type: %s\n", yamlString("salamander"))
		fmt.Fprintf(&b, "  salamander:\n")
		fmt.Fprintf(&b, "    password: %s\n", yamlString(c.ObfsPassword))
	}
	if c.BandwidthUp != "" || c.BandwidthDown != "" {
		fmt.Fprintf(&b, "bandwidth:\n")
		if c.BandwidthUp != "" {
			fmt.Fprintf(&b, "  up: %s\n", yamlString(c.BandwidthUp))
		}
		if c.BandwidthDown != "" {
			fmt.Fprintf(&b, "  down: %s\n", yamlString(c.BandwidthDown))
		}
	}
	if c.MasqueradeURL != "" {
		fmt.Fprintf(&b, "masquerade:\n")
		fmt.Fprintf(&b, "  type: %s\n", yamlString("proxy"))
		fmt.Fprintf(&b, "  proxy:\n")
		fmt.Fprintf(&b, "    url: %s\n", yamlString(c.MasqueradeURL))
		fmt.Fprintf(&b, "    rewriteHost: %t\n", c.MasqueradeRewriteHost)
	}
	return b.String(), nil
}

func (c RealityServerConfig) Validate() error {
	if _, _, err := splitEndpoint(c.Listen); err != nil {
		return fmt.Errorf("invalid reality listen: %w", err)
	}
	if strings.TrimSpace(c.UUID) == "" {
		return fmt.Errorf("reality uuid is required")
	}
	if strings.TrimSpace(c.PrivateKey) == "" {
		return fmt.Errorf("reality private key is required")
	}
	if _, _, err := splitEndpoint(c.Dest); err != nil {
		return fmt.Errorf("invalid reality dest: %w", err)
	}
	if len(c.ServerNames) > 0 {
		if err := validateStringList("reality server names", c.ServerNames); err != nil {
			return err
		}
	}
	if len(c.ShortIDs) > 0 {
		if err := validateStringList("reality short ids", c.ShortIDs); err != nil {
			return err
		}
	}
	return nil
}

func (c RealityServerConfig) Render() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	listenHost, listenPort, _ := splitEndpoint(c.Listen)
	destHost, _, _ := splitEndpoint(c.Dest)
	serverNames := sortedStrings(c.ServerNames)
	if len(serverNames) == 0 {
		serverNames = []string{destHost}
	}

	rendered := xrayServerConfig{
		Log: xrayLogConfig{LogLevel: "warning"},
		Inbounds: []xrayServerInbound{{
			Listen:   listenHost,
			Port:     listenPort,
			Protocol: "vless",
			Settings: xrayVLESSInboundSettings{
				Clients: []xrayVLESSInboundClient{{
					ID:   c.UUID,
					Flow: c.Flow,
				}},
				Decryption: "none",
			},
			StreamSettings: xrayServerStreamSettings{
				Network:  "tcp",
				Security: "reality",
				RealitySettings: xrayServerRealitySettings{
					Show:        false,
					Dest:        c.Dest,
					ServerNames: serverNames,
					PrivateKey:  c.PrivateKey,
					ShortIDs:    sortedStrings(c.ShortIDs),
				},
			},
		}},
		Outbounds: []xrayServerOutbound{{
			Protocol: "freedom",
		}},
	}
	return marshalJSON(rendered)
}

func (c TUICServerConfig) Validate() error {
	if _, _, err := splitEndpoint(c.Listen); err != nil {
		return fmt.Errorf("invalid tuic listen: %w", err)
	}
	if len(c.Users) == 0 {
		return fmt.Errorf("tuic users are required")
	}
	for uuid, password := range c.Users {
		if strings.TrimSpace(uuid) == "" {
			return fmt.Errorf("tuic user uuid is required")
		}
		if strings.TrimSpace(password) == "" {
			return fmt.Errorf("tuic user %q password is required", uuid)
		}
	}
	if strings.TrimSpace(c.CertFile) == "" {
		return fmt.Errorf("tuic tls cert file is required")
	}
	if strings.TrimSpace(c.KeyFile) == "" {
		return fmt.Errorf("tuic tls key file is required")
	}
	if len(c.ALPN) > 0 {
		if err := validateStringList("tuic alpn", c.ALPN); err != nil {
			return err
		}
	}
	return nil
}

func (c TUICServerConfig) Render() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	users := make(map[string]string, len(c.Users))
	for uuid, password := range c.Users {
		users[uuid] = password
	}
	rendered := tuicServerConfig{
		Server:            c.Listen,
		Users:             users,
		Certificate:       c.CertFile,
		PrivateKey:        c.KeyFile,
		CongestionControl: firstNonEmpty(c.CongestionControl, "bbr"),
		ALPN:              sortedStrings(c.ALPN),
		ZeroRTTHandshake:  c.ZeroRTTHandshake,
		LogLevel:          "warn",
	}
	return marshalJSON(rendered)
}

type xrayServerConfig struct {
	Log       xrayLogConfig        `json:"log"`
	Inbounds  []xrayServerInbound  `json:"inbounds"`
	Outbounds []xrayServerOutbound `json:"outbounds"`
}

type xrayServerInbound struct {
	Listen         string                   `json:"listen"`
	Port           int                      `json:"port"`
	Protocol       string                   `json:"protocol"`
	Settings       xrayVLESSInboundSettings `json:"settings"`
	StreamSettings xrayServerStreamSettings `json:"streamSettings"`
}

type xrayVLESSInboundSettings struct {
	Clients    []xrayVLESSInboundClient `json:"clients"`
	Decryption string                   `json:"decryption"`
}

type xrayVLESSInboundClient struct {
	ID   string `json:"id"`
	Flow string `json:"flow,omitempty"`
}

type xrayServerStreamSettings struct {
	Network         string                    `json:"network"`
	Security        string                    `json:"security"`
	RealitySettings xrayServerRealitySettings `json:"realitySettings"`
}

type xrayServerRealitySettings struct {
	Show        bool     `json:"show"`
	Dest        string   `json:"dest"`
	ServerNames []string `json:"serverNames"`
	PrivateKey  string   `json:"privateKey"`
	ShortIDs    []string `json:"shortIds,omitempty"`
}

type xrayServerOutbound struct {
	Protocol string `json:"protocol"`
}

type tuicServerConfig struct {
	Server                 string            `json:"server"`
	Users                  map[string]string `json:"users"`
	Certificate            string            `json:"certificate"`
	PrivateKey             string            `json:"private_key"`
	CongestionControl      string            `json:"congestion_control"`
	ALPN                   []string          `json:"alpn,omitempty"`
	UDPRelayIPv6           bool              `json:"udp_relay_ipv6,omitempty"`
	ZeroRTTHandshake       bool              `json:"zero_rtt_handshake"`
	DualStack              bool              `json:"dual_stack,omitempty"`
	AuthTimeout            string            `json:"auth_timeout,omitempty"`
	TaskNegotiationTimeout string            `json:"task_negotiation_timeout,omitempty"`
	MaxIdleTime            string            `json:"max_idle_time,omitempty"`
	MaxExternalPacketSize  int               `json:"max_external_packet_size,omitempty"`
	SendWindow             int               `json:"send_window,omitempty"`
	ReceiveWindow          int               `json:"receive_window,omitempty"`
	GCInterval             string            `json:"gc_interval,omitempty"`
	GCLifetime             string            `json:"gc_lifetime,omitempty"`
	LogLevel               string            `json:"log_level,omitempty"`
}
