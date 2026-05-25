package desktop

import (
	"fmt"
	"time"

	"anixops-sd-wan/internal/agent"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/transport"
)

type LinkStatus struct {
	LinkClass     transport.LinkClass `json:"link_class"`
	Protocol      transport.Protocol  `json:"protocol"`
	EgressNodeID  string              `json:"egress_node_id"`
	RTTMillis     int                 `json:"rtt_millis"`
	PacketLossPpm int                 `json:"packet_loss_ppm"`
	JitterMillis  int                 `json:"jitter_millis"`
	UDPAvailable  bool                `json:"udp_available"`
}

type CertificateStatus struct {
	Serial    string    `json:"serial"`
	NotAfter  time.Time `json:"not_after"`
	Revoked   bool      `json:"revoked"`
	ExpiresIn string    `json:"expires_in"`
}

type DesktopPage struct {
	Title string   `json:"title"`
	Lines []string `json:"lines"`
}

type ViewModel struct {
	DeviceID      string              `json:"device_id"`
	TenantID      string              `json:"tenant_id"`
	Platform      string              `json:"platform"`
	Running       bool                `json:"running"`
	ConfigVersion string              `json:"config_version"`
	Config        domain.ConfigBundle `json:"config"`
	Link          LinkStatus          `json:"link"`
	Certificate   CertificateStatus   `json:"certificate"`
	LogSummary    []string            `json:"log_summary"`
	Alerts        []string            `json:"alerts"`
	UpdatedAt     time.Time           `json:"updated_at"`
}

func NewViewModel(snapshot agent.Snapshot, link LinkStatus, cert CertificateStatus, logs []string) (ViewModel, error) {
	if snapshot.DeviceID == "" {
		return ViewModel{}, fmt.Errorf("device id is required")
	}
	if snapshot.TenantID == "" {
		return ViewModel{}, fmt.Errorf("tenant id is required")
	}
	if !transport.KnownProtocol(link.Protocol) {
		return ViewModel{}, fmt.Errorf("unknown protocol %q", link.Protocol)
	}

	model := ViewModel{
		DeviceID:      snapshot.DeviceID,
		TenantID:      snapshot.TenantID,
		Platform:      snapshot.Platform,
		Running:       snapshot.Running,
		ConfigVersion: snapshot.ConfigVersion,
		Link:          link,
		Certificate:   cert,
		LogSummary:    append([]string(nil), logs...),
		UpdatedAt:     snapshot.UpdatedAt,
	}
	model.Alerts = model.deriveAlerts()
	return model, nil
}

func (m ViewModel) Pages() []DesktopPage {
	return []DesktopPage{
		{
			Title: "Overview",
			Lines: []string{
				"Tenant: " + m.TenantID,
				"Device: " + m.DeviceID,
				"Platform: " + m.Platform,
				"Agent: " + m.agentStatus(),
				"Config version: " + m.ConfigVersion,
			},
		},
		{
			Title: "Connection status",
			Lines: []string{
				"Link class: " + string(m.Link.LinkClass),
				"Protocol: " + m.Link.Protocol.String(),
				"Egress node: " + nonEmpty(m.Link.EgressNodeID, "unassigned"),
				"RTT: " + fmt.Sprintf("%d ms", m.Link.RTTMillis),
				"Loss: " + fmt.Sprintf("%d ppm", m.Link.PacketLossPpm),
				"Jitter: " + fmt.Sprintf("%d ms", m.Link.JitterMillis),
				"UDP available: " + fmt.Sprintf("%t", m.Link.UDPAvailable),
			},
		},
		{
			Title: "Protocol switching",
			Lines: []string{
				"Current entry protocol: " + m.Link.Protocol.String(),
				"Fallback path: Hysteria2 -> REALITY -> TUIC -> WireGuard",
				"Selection signals: link class, RTT, loss, jitter, UDP availability",
			},
		},
		{
			Title: "Nodes",
			Lines: []string{
				"Current egress node: " + nonEmpty(m.Link.EgressNodeID, "unassigned"),
				"Node inventory is provided by the control plane when available.",
			},
		},
		{
			Title: "Policies",
			Lines: []string{
				"Policy evaluation is driven by the control plane.",
				"Config version: " + m.ConfigVersion,
			},
		},
		{
			Title: "Diagnostics",
			Lines: append([]string{"Last updated: " + m.UpdatedAt.Format(time.RFC3339)}, m.Alerts...),
		},
		{
			Title: "Logs",
			Lines: append([]string(nil), m.LogSummary...),
		},
		{
			Title: "Certificates",
			Lines: []string{
				"Serial: " + nonEmpty(m.Certificate.Serial, "unknown"),
				"Revoked: " + fmt.Sprintf("%t", m.Certificate.Revoked),
				"Expires: " + renderCertificateExpiry(m.Certificate.NotAfter),
			},
		},
		{
			Title: "Updates",
			Lines: []string{
				"Current config version: " + m.ConfigVersion,
				"Last sync: " + m.UpdatedAt.Format(time.RFC3339),
			},
		},
		{
			Title: "Settings",
			Lines: []string{
				"Desktop UI can apply local config through the agent.",
				"Current transport: " + nonEmpty(m.Config.Values["transport"], m.Link.Protocol.String()),
				"Agent settings are managed by the control plane and local service layer.",
			},
		},
	}
}

func (m ViewModel) deriveAlerts() []string {
	var alerts []string
	if !m.Running {
		alerts = append(alerts, "agent stopped")
	}
	if !m.Link.UDPAvailable {
		alerts = append(alerts, "udp unavailable")
	}
	if m.Certificate.Revoked {
		alerts = append(alerts, "certificate revoked")
	}
	if !m.Certificate.NotAfter.IsZero() {
		remaining := time.Until(m.Certificate.NotAfter)
		if remaining < 7*24*time.Hour && remaining > 0 {
			alerts = append(alerts, "certificate expires soon")
		}
	}
	return alerts
}

func (m ViewModel) agentStatus() string {
	if m.Running {
		return "running"
	}
	return "stopped"
}

func nonEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func renderCertificateExpiry(ts time.Time) string {
	if ts.IsZero() {
		return "unknown"
	}
	return ts.Format(time.RFC3339)
}
