package desktop

import (
	"testing"
	"time"

	"anixops-sd-wan/internal/agent"
	"anixops-sd-wan/internal/transport"
)

func TestRunSelfCheckPassesOnHealthyModel(t *testing.T) {
	result := RunSelfCheck(ViewModel{
		DeviceID:      "device-a",
		TenantID:      "tenant-a",
		ConfigVersion: "v1",
		Running:       true,
		Link: LinkStatus{
			Protocol:     transport.ProtocolHysteria2,
			UDPAvailable: true,
		},
	})

	if !result.Passed {
		t.Fatalf("expected self-check to pass, got %+v", result)
	}
}

func TestRunSelfCheckFlagsMissingIdentityAndStoppedAgent(t *testing.T) {
	result := RunSelfCheck(ViewModel{
		ConfigVersion: "v1",
		Running:       false,
		Link: LinkStatus{
			Protocol: transport.ProtocolReality,
		},
	})

	if result.Passed {
		t.Fatalf("expected self-check to fail, got %+v", result)
	}
}

func TestViewModelDiagnosticsPageIncludesSelfCheck(t *testing.T) {
	model, err := NewViewModel(agent.Snapshot{
		TenantID:      "tenant-a",
		DeviceID:      "device-a",
		Platform:      "linux/amd64",
		Running:       true,
		ConfigVersion: "v1",
		UpdatedAt:     time.Now().UTC(),
	}, LinkStatus{
		Protocol:     transport.ProtocolWireGuard,
		UDPAvailable: true,
	}, CertificateStatus{}, nil)
	if err != nil {
		t.Fatalf("new view model: %v", err)
	}

	pages := model.Pages()
	if pages[5].Title != "Diagnostics" {
		t.Fatalf("expected diagnostics page, got %+v", pages[5])
	}
}
