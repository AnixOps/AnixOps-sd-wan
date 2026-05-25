package transport

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	WireGuardConfigFile = "wireguard.conf"
	Hysteria2ConfigFile = "hysteria2.yaml"
	RealityConfigFile   = "reality.json"
	TUICConfigFile      = "tuic.json"
)

type RenderedClientConfig struct {
	Protocol Protocol
	FileName string
	Content  string
	Perm     os.FileMode
}

type ClientConfigWriter interface {
	WriteFile(path string, data []byte, perm os.FileMode) error
}

type ClientConfigSet struct {
	WireGuard *WireGuardClientConfig
	Hysteria2 *Hysteria2ClientConfig
	Reality   *RealityClientConfig
	TUIC      *TUICClientConfig
}

type WireGuardClientConfig struct {
	PrivateKey string
	Address    string
	DNS        []string
	MTU        int
	Peer       WireGuardClientPeer
}

type WireGuardClientPeer struct {
	PublicKey                  string
	Endpoint                   string
	AllowedIPs                 []string
	PersistentKeepaliveSeconds int
}

type Hysteria2ClientConfig struct {
	Server        string
	Auth          string
	SNI           string
	Insecure      bool
	ALPN          []string
	PinSHA256     string
	ObfsPassword  string
	Socks5Listen  string
	HTTPListen    string
	BandwidthUp   string
	BandwidthDown string
}

type RealityClientConfig struct {
	Server           string
	UUID             string
	ServerName       string
	PublicKey        string
	ShortID          string
	SpiderX          string
	Fingerprint      string
	Flow             string
	LocalSocksListen string
}

type TUICClientConfig struct {
	Server            string
	UUID              string
	Password          string
	SNI               string
	Insecure          bool
	Certificates      []string
	ALPN              []string
	CongestionControl string
	UDPRelayMode      string
	LocalSocksListen  string
}

func ConfigFileName(protocol Protocol) (string, error) {
	switch protocol {
	case ProtocolWireGuard:
		return WireGuardConfigFile, nil
	case ProtocolHysteria2:
		return Hysteria2ConfigFile, nil
	case ProtocolReality:
		return RealityConfigFile, nil
	case ProtocolTUIC:
		return TUICConfigFile, nil
	default:
		return "", fmt.Errorf("unknown protocol %q", protocol)
	}
}

func ConfigPath(configDir string, protocol Protocol) (string, error) {
	fileName, err := ConfigFileName(protocol)
	if err != nil {
		return "", err
	}
	return filepath.Join(normalizeConfigDir(configDir), fileName), nil
}

func (s ClientConfigSet) RenderAll() ([]RenderedClientConfig, error) {
	var rendered []RenderedClientConfig
	if s.WireGuard != nil {
		content, err := s.WireGuard.Render()
		if err != nil {
			return nil, err
		}
		rendered = append(rendered, RenderedClientConfig{
			Protocol: ProtocolWireGuard,
			FileName: WireGuardConfigFile,
			Content:  content,
			Perm:     0o600,
		})
	}
	if s.Hysteria2 != nil {
		content, err := s.Hysteria2.Render()
		if err != nil {
			return nil, err
		}
		rendered = append(rendered, RenderedClientConfig{
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
		rendered = append(rendered, RenderedClientConfig{
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
		rendered = append(rendered, RenderedClientConfig{
			Protocol: ProtocolTUIC,
			FileName: TUICConfigFile,
			Content:  content,
			Perm:     0o600,
		})
	}
	if len(rendered) == 0 {
		return nil, fmt.Errorf("at least one client transport config is required")
	}
	return rendered, nil
}

func (s ClientConfigSet) WriteAll(configDir string, writer ClientConfigWriter) error {
	if writer == nil {
		return fmt.Errorf("client config writer is required")
	}
	rendered, err := s.RenderAll()
	if err != nil {
		return err
	}
	for _, item := range rendered {
		path, err := ConfigPath(configDir, item.Protocol)
		if err != nil {
			return err
		}
		if err := writer.WriteFile(path, []byte(item.Content), item.Perm); err != nil {
			return fmt.Errorf("write %s client config: %w", item.Protocol, err)
		}
	}
	return nil
}

func (c WireGuardClientConfig) Validate() error {
	if strings.TrimSpace(c.PrivateKey) == "" {
		return fmt.Errorf("wireguard private key is required")
	}
	if _, _, err := net.ParseCIDR(c.Address); err != nil {
		return fmt.Errorf("invalid wireguard address: %w", err)
	}
	if c.MTU < 0 || c.MTU > 9000 {
		return fmt.Errorf("wireguard mtu must be between 0 and 9000")
	}
	for _, dns := range c.DNS {
		if net.ParseIP(dns) == nil {
			return fmt.Errorf("invalid wireguard dns server %q", dns)
		}
	}
	if err := c.Peer.Validate(); err != nil {
		return err
	}
	return nil
}

func (p WireGuardClientPeer) Validate() error {
	if strings.TrimSpace(p.PublicKey) == "" {
		return fmt.Errorf("wireguard peer public key is required")
	}
	if _, _, err := splitEndpoint(p.Endpoint); err != nil {
		return fmt.Errorf("invalid wireguard peer endpoint: %w", err)
	}
	if len(p.AllowedIPs) == 0 {
		return fmt.Errorf("wireguard peer allowed ips are required")
	}
	for _, allowed := range p.AllowedIPs {
		if _, _, err := net.ParseCIDR(allowed); err != nil {
			return fmt.Errorf("invalid wireguard peer allowed ip %q: %w", allowed, err)
		}
	}
	if p.PersistentKeepaliveSeconds < 0 || p.PersistentKeepaliveSeconds > 65535 {
		return fmt.Errorf("wireguard persistent keepalive must be between 0 and 65535")
	}
	return nil
}

func (c WireGuardClientConfig) Render() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	dns := append([]string(nil), c.DNS...)
	sort.Strings(dns)
	allowedIPs := append([]string(nil), c.Peer.AllowedIPs...)
	sort.Strings(allowedIPs)

	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\n", c.Address)
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.PrivateKey)
	if len(dns) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(dns, ", "))
	}
	if c.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", c.MTU)
	}
	fmt.Fprintf(&b, "\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", c.Peer.PublicKey)
	fmt.Fprintf(&b, "Endpoint = %s\n", c.Peer.Endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowedIPs, ", "))
	if c.Peer.PersistentKeepaliveSeconds > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", c.Peer.PersistentKeepaliveSeconds)
	}
	return b.String(), nil
}

func (c Hysteria2ClientConfig) Validate() error {
	if _, _, err := splitEndpoint(c.Server); err != nil {
		return fmt.Errorf("invalid hysteria2 server: %w", err)
	}
	if strings.TrimSpace(c.Auth) == "" {
		return fmt.Errorf("hysteria2 auth is required")
	}
	if c.Socks5Listen != "" {
		if _, _, err := splitEndpoint(c.Socks5Listen); err != nil {
			return fmt.Errorf("invalid hysteria2 socks5 listen: %w", err)
		}
	}
	if c.HTTPListen != "" {
		if _, _, err := splitEndpoint(c.HTTPListen); err != nil {
			return fmt.Errorf("invalid hysteria2 http listen: %w", err)
		}
	}
	if len(c.ALPN) > 0 {
		if err := validateStringList("hysteria2 alpn", c.ALPN); err != nil {
			return err
		}
	}
	return nil
}

func (c Hysteria2ClientConfig) Render() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	host, _, _ := splitEndpoint(c.Server)
	sni := firstNonEmpty(c.SNI, host)

	var b strings.Builder
	fmt.Fprintf(&b, "server: %s\n", yamlString(c.Server))
	fmt.Fprintf(&b, "auth: %s\n", yamlString(c.Auth))
	fmt.Fprintf(&b, "tls:\n")
	fmt.Fprintf(&b, "  sni: %s\n", yamlString(sni))
	fmt.Fprintf(&b, "  insecure: %t\n", c.Insecure)
	if c.PinSHA256 != "" {
		fmt.Fprintf(&b, "  pinSHA256: %s\n", yamlString(c.PinSHA256))
	}
	if len(c.ALPN) > 0 {
		fmt.Fprintf(&b, "  alpn:\n")
		for _, value := range sortedStrings(c.ALPN) {
			fmt.Fprintf(&b, "    - %s\n", yamlString(value))
		}
	}
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
	if c.Socks5Listen != "" {
		fmt.Fprintf(&b, "socks5:\n")
		fmt.Fprintf(&b, "  listen: %s\n", yamlString(c.Socks5Listen))
	}
	if c.HTTPListen != "" {
		fmt.Fprintf(&b, "http:\n")
		fmt.Fprintf(&b, "  listen: %s\n", yamlString(c.HTTPListen))
	}
	return b.String(), nil
}

func (c RealityClientConfig) Validate() error {
	if _, _, err := splitEndpoint(c.Server); err != nil {
		return fmt.Errorf("invalid reality server: %w", err)
	}
	if strings.TrimSpace(c.UUID) == "" {
		return fmt.Errorf("reality uuid is required")
	}
	if strings.TrimSpace(c.PublicKey) == "" {
		return fmt.Errorf("reality public key is required")
	}
	if c.LocalSocksListen != "" {
		if _, _, err := splitEndpoint(c.LocalSocksListen); err != nil {
			return fmt.Errorf("invalid reality local socks listen: %w", err)
		}
	}
	return nil
}

func (c RealityClientConfig) Render() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	host, port, _ := splitEndpoint(c.Server)
	listenHost, listenPort, err := splitEndpoint(firstNonEmpty(c.LocalSocksListen, "127.0.0.1:1080"))
	if err != nil {
		return "", err
	}
	serverName := firstNonEmpty(c.ServerName, host)
	spiderX := firstNonEmpty(c.SpiderX, "/")
	fingerprint := firstNonEmpty(c.Fingerprint, "chrome")

	rendered := xrayClientConfig{
		Log: xrayLogConfig{LogLevel: "warning"},
		Inbounds: []xrayInbound{{
			Listen:   listenHost,
			Port:     listenPort,
			Protocol: "socks",
			Settings: xraySocksInboundSettings{Auth: "noauth", UDP: true},
		}},
		Outbounds: []xrayOutbound{{
			Protocol: "vless",
			Settings: xrayVLESSSettings{VNext: []xrayVNext{{
				Address: host,
				Port:    port,
				Users: []xrayVLESSUser{{
					ID:         c.UUID,
					Encryption: "none",
					Flow:       c.Flow,
				}},
			}}},
			StreamSettings: xrayStreamSettings{
				Network:  "tcp",
				Security: "reality",
				RealitySettings: xrayRealitySettings{
					ServerName:  serverName,
					Fingerprint: fingerprint,
					PublicKey:   c.PublicKey,
					ShortID:     c.ShortID,
					SpiderX:     spiderX,
				},
			},
		}},
	}
	return marshalJSON(rendered)
}

func (c TUICClientConfig) Validate() error {
	if _, _, err := splitEndpoint(c.Server); err != nil {
		return fmt.Errorf("invalid tuic server: %w", err)
	}
	if strings.TrimSpace(c.UUID) == "" {
		return fmt.Errorf("tuic uuid is required")
	}
	if strings.TrimSpace(c.Password) == "" {
		return fmt.Errorf("tuic password is required")
	}
	if c.LocalSocksListen != "" {
		if _, _, err := splitEndpoint(c.LocalSocksListen); err != nil {
			return fmt.Errorf("invalid tuic local socks listen: %w", err)
		}
	}
	for _, certificate := range c.Certificates {
		if strings.TrimSpace(certificate) == "" {
			return fmt.Errorf("tuic certificates cannot contain empty values")
		}
	}
	if len(c.ALPN) > 0 {
		if err := validateStringList("tuic alpn", c.ALPN); err != nil {
			return err
		}
	}
	return nil
}

func (c TUICClientConfig) Render() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	host, _, _ := splitEndpoint(c.Server)
	listen := firstNonEmpty(c.LocalSocksListen, "127.0.0.1:1080")
	rendered := tuicClientConfig{
		Relay: tuicClientRelayConfig{
			Server:             c.Server,
			UUID:               c.UUID,
			Password:           c.Password,
			IP:                 host,
			Certificates:       append([]string(nil), c.Certificates...),
			CongestionControl:  firstNonEmpty(c.CongestionControl, "bbr"),
			UDPRelayMode:       firstNonEmpty(c.UDPRelayMode, "native"),
			ALPN:               sortedStrings(c.ALPN),
			ZeroRTTHandshake:   false,
			DisableSNI:         false,
			DisableNativeCerts: c.Insecure,
		},
		Local: tuicClientLocalConfig{
			Server:        listen,
			DualStack:     false,
			MaxPacketSize: 1500,
		},
		LogLevel: "warn",
	}
	return marshalJSON(rendered)
}

type xrayClientConfig struct {
	Log       xrayLogConfig  `json:"log"`
	Inbounds  []xrayInbound  `json:"inbounds"`
	Outbounds []xrayOutbound `json:"outbounds"`
}

type xrayLogConfig struct {
	LogLevel string `json:"loglevel"`
}

type xrayInbound struct {
	Listen   string                   `json:"listen"`
	Port     int                      `json:"port"`
	Protocol string                   `json:"protocol"`
	Settings xraySocksInboundSettings `json:"settings"`
}

type xraySocksInboundSettings struct {
	Auth string `json:"auth"`
	UDP  bool   `json:"udp"`
}

type xrayOutbound struct {
	Protocol       string             `json:"protocol"`
	Settings       xrayVLESSSettings  `json:"settings"`
	StreamSettings xrayStreamSettings `json:"streamSettings"`
}

type xrayVLESSSettings struct {
	VNext []xrayVNext `json:"vnext"`
}

type xrayVNext struct {
	Address string          `json:"address"`
	Port    int             `json:"port"`
	Users   []xrayVLESSUser `json:"users"`
}

type xrayVLESSUser struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow,omitempty"`
}

type xrayStreamSettings struct {
	Network         string              `json:"network"`
	Security        string              `json:"security"`
	RealitySettings xrayRealitySettings `json:"realitySettings"`
}

type xrayRealitySettings struct {
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId,omitempty"`
	SpiderX     string `json:"spiderX"`
}

type tuicClientConfig struct {
	Relay    tuicClientRelayConfig `json:"relay"`
	Local    tuicClientLocalConfig `json:"local"`
	LogLevel string                `json:"log_level"`
}

type tuicClientRelayConfig struct {
	Server             string   `json:"server"`
	UUID               string   `json:"uuid"`
	Password           string   `json:"password"`
	IP                 string   `json:"ip,omitempty"`
	Certificates       []string `json:"certificates,omitempty"`
	CongestionControl  string   `json:"congestion_control"`
	UDPRelayMode       string   `json:"udp_relay_mode"`
	ALPN               []string `json:"alpn,omitempty"`
	ZeroRTTHandshake   bool     `json:"zero_rtt_handshake"`
	DisableSNI         bool     `json:"disable_sni"`
	DisableNativeCerts bool     `json:"disable_native_certs"`
	SendWindow         int      `json:"send_window,omitempty"`
	ReceiveWindow      int      `json:"receive_window,omitempty"`
	GCInterval         string   `json:"gc_interval,omitempty"`
	GCLifetime         string   `json:"gc_lifetime,omitempty"`
}

type tuicClientLocalConfig struct {
	Server        string `json:"server"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	DualStack     bool   `json:"dual_stack,omitempty"`
	MaxPacketSize int    `json:"max_packet_size,omitempty"`
}

func marshalJSON(value interface{}) (string, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

func normalizeConfigDir(configDir string) string {
	configDir = strings.TrimSpace(configDir)
	if configDir == "" {
		return "/etc/anixops"
	}
	return configDir
}

func splitEndpoint(endpoint string) (string, int, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", 0, fmt.Errorf("endpoint is required")
	}
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", 0, err
	}
	if strings.TrimSpace(host) == "" {
		return "", 0, fmt.Errorf("host is required")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q: %w", portText, err)
	}
	if port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("port must be between 1 and 65535")
	}
	return host, port, nil
}

func validateStringList(name string, values []string) error {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s cannot contain empty values", name)
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func yamlString(value string) string {
	return strconv.Quote(value)
}
