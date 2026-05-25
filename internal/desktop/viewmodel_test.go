package desktop

import (
	"testing"
	"time"

	"anixops-sd-wan/internal/agent"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/transport"
)

func TestViewModelIncludesRequiredStatusFields(t *testing.T) {
	model, err := NewViewModel(agent.Snapshot{
		TenantID:      "tenant-a",
		DeviceID:      "agent-a",
		Platform:      "linux/amd64",
		Running:       true,
		ConfigVersion: "v1",
		UpdatedAt:     time.Date(2026, 5, 12, 0, 0, 0, 0, time.UTC),
	}, LinkStatus{
		LinkClass:    transport.LinkPublic,
		Protocol:     transport.ProtocolHysteria2,
		EgressNodeID: "jp-egress",
		RTTMillis:    42,
		UDPAvailable: true,
	}, CertificateStatus{
		Serial:   "cert-a",
		NotAfter: time.Now().Add(30 * 24 * time.Hour),
	}, []string{"connected"})
	if err != nil {
		t.Fatalf("new view model: %v", err)
	}

	if model.DeviceID != "agent-a" || model.Link.EgressNodeID != "jp-egress" {
		t.Fatalf("unexpected model: %+v", model)
	}
	if len(model.Alerts) != 0 {
		t.Fatalf("expected no alerts, got %+v", model.Alerts)
	}
}

func TestViewModelAlertsOnStoppedAgentAndRevokedCertificate(t *testing.T) {
	model, err := NewViewModel(agent.Snapshot{
		TenantID:      "tenant-a",
		DeviceID:      "agent-a",
		Platform:      "linux/amd64",
		ConfigVersion: "v1",
		UpdatedAt:     time.Now(),
	}, LinkStatus{
		LinkClass:    transport.LinkPublic,
		Protocol:     transport.ProtocolReality,
		UDPAvailable: false,
	}, CertificateStatus{
		Serial:  "cert-a",
		Revoked: true,
	}, nil)
	if err != nil {
		t.Fatalf("new view model: %v", err)
	}

	if len(model.Alerts) != 3 {
		t.Fatalf("expected three alerts, got %+v", model.Alerts)
	}
}

func TestViewModelPagesCoverDesktopAreas(t *testing.T) {
	model, err := NewViewModel(agent.Snapshot{
		TenantID:      "tenant-a",
		DeviceID:      "agent-a",
		Platform:      "linux/amd64",
		Running:       true,
		ConfigVersion: "v1",
		UpdatedAt:     time.Now(),
	}, LinkStatus{
		LinkClass:    transport.LinkDedicated,
		Protocol:     transport.ProtocolWireGuard,
		EgressNodeID: "core-1",
		UDPAvailable: true,
	}, CertificateStatus{}, []string{"loaded"})
	if err != nil {
		t.Fatalf("new view model: %v", err)
	}

	pages := model.Pages()
	if len(pages) != 10 {
		t.Fatalf("expected ten desktop pages, got %d", len(pages))
	}
	expectedTitles := []string{
		"Overview",
		"Connection status",
		"Protocol switching",
		"Nodes",
		"Policies",
		"Diagnostics",
		"Logs",
		"Certificates",
		"Updates",
		"Settings",
	}
	for i, page := range pages {
		if page.Title != expectedTitles[i] {
			t.Fatalf("unexpected page title at %d: got %q want %q", i, page.Title, expectedTitles[i])
		}
	}
}

func TestViewModelSettingsPageShowsConfigTransport(t *testing.T) {
	model, err := NewViewModel(agent.Snapshot{
		TenantID:      "tenant-a",
		DeviceID:      "agent-a",
		Platform:      "linux/amd64",
		Running:       true,
		ConfigVersion: "v1",
		UpdatedAt:     time.Now(),
	}, LinkStatus{
		LinkClass:    transport.LinkDedicated,
		Protocol:     transport.ProtocolWireGuard,
		EgressNodeID: "core-1",
		UDPAvailable: true,
	}, CertificateStatus{}, nil)
	if err != nil {
		t.Fatalf("new view model: %v", err)
	}
	model.Config = domain.ConfigBundle{
		ID:       "cfg-local",
		TenantID: "tenant-a",
		TargetID: "agent-a",
		Version:  "v2",
		Values:   map[string]string{"transport": "reality"},
	}

	pages := model.Pages()
	settings := pages[len(pages)-1]
	if settings.Title != "Settings" {
		t.Fatalf("expected settings page, got %+v", settings)
	}
	found := false
	foundApply := false
	for _, line := range settings.Lines {
		if line == "Desktop UI can apply local config through the agent." {
			foundApply = true
		}
		if line == "Current transport: reality" {
			found = true
			break
		}
	}
	if !foundApply {
		t.Fatalf("expected settings page to describe local config apply capability, got %+v", settings.Lines)
	}
	if !found {
		t.Fatalf("expected settings page to show config transport, got %+v", settings.Lines)
	}
}

func TestNewViewModelRejectsUnknownProtocol(t *testing.T) {
	if _, err := NewViewModel(agent.Snapshot{
		TenantID:      "tenant-a",
		DeviceID:      "agent-a",
		Platform:      "linux/amd64",
		Running:       true,
		ConfigVersion: "v1",
		UpdatedAt:     time.Now(),
	}, LinkStatus{
		Protocol: "unsupported",
	}, CertificateStatus{}, nil); err == nil {
		t.Fatal("expected unknown protocol to be rejected")
	}
}

func TestViewModelAlertsOnExpiringCertificate(t *testing.T) {
	model, err := NewViewModel(agent.Snapshot{
		TenantID:      "tenant-a",
		DeviceID:      "agent-a",
		Platform:      "linux/amd64",
		Running:       true,
		ConfigVersion: "v1",
		UpdatedAt:     time.Now(),
	}, LinkStatus{
		Protocol:     transport.ProtocolWireGuard,
		UDPAvailable: true,
	}, CertificateStatus{
		NotAfter: time.Now().Add(24 * time.Hour),
	}, nil)
	if err != nil {
		t.Fatalf("new view model: %v", err)
	}
	found := false
	for _, alert := range model.Alerts {
		if alert == "certificate expires soon" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected certificate expiry alert, got %+v", model.Alerts)
	}
}
