//go:build fyne

package desktop

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"anixops-sd-wan/internal/agent"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/transport"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"fyne.io/fyne/v2/test"
)

func TestRenderSelfCheckSectionExposesRunButton(t *testing.T) {
	obj := renderSelfCheckSection(ViewModel{})
	box, ok := obj.(*fyne.Container)
	if !ok {
		t.Fatalf("expected container, got %T", obj)
	}
	if len(box.Objects) < 3 {
		t.Fatalf("expected self-check section to expose label/button/results, got %d objects", len(box.Objects))
	}
	button, ok := box.Objects[1].(*widget.Button)
	if !ok {
		t.Fatalf("expected run button, got %T", box.Objects[1])
	}
	if button.Text != "Run Self-check" {
		t.Fatalf("expected run self-check button, got %q", button.Text)
	}
	if _, ok := box.Objects[2].(*widget.Label); !ok {
		t.Fatalf("expected status label, got %T", box.Objects[2])
	}
	if _, ok := box.Objects[3].(*widget.Label); !ok {
		t.Fatalf("expected result label, got %T", box.Objects[3])
	}
}

func TestRenderDiagnosticsPageIncludesSelfCheckSection(t *testing.T) {
	page := DesktopPage{Title: "Diagnostics", Lines: []string{"Last updated: now"}}
	obj := renderPage(page, ViewModel{}, nil, AutostartOptions{})
	scroll, ok := obj.(*container.Scroll)
	if !ok {
		t.Fatalf("expected scroll container, got %T", obj)
	}
	content, ok := scroll.Content.(*fyne.Container)
	if !ok {
		t.Fatalf("expected inner container, got %T", scroll.Content)
	}
	if !containsLabelText(content, "Self-check") {
		t.Fatalf("expected diagnostics page to contain self-check section")
	}
}

func TestRenderSettingsPageIncludesAutostartSection(t *testing.T) {
	page := DesktopPage{Title: "Settings", Lines: []string{"Desktop UI can apply local config through the agent."}}
	obj := renderPage(page, ViewModel{}, nil, AutostartOptions{
		AppName:  "AnixOps SD-WAN",
		ExecPath: "/opt/anixops/anix-ui",
		HomeDir:  "/home/test",
	})
	scroll, ok := obj.(*container.Scroll)
	if !ok {
		t.Fatalf("expected scroll container, got %T", obj)
	}
	content, ok := scroll.Content.(*fyne.Container)
	if !ok {
		t.Fatalf("expected inner container, got %T", scroll.Content)
	}
	if !containsLabelText(content, "Start at login") {
		t.Fatalf("expected settings page to contain autostart section")
	}
	if !containsLabelContains(content, "Current state:") {
		t.Fatalf("expected settings page to show autostart state")
	}
}

func TestRenderAutostartSectionButtonsRoundTrip(t *testing.T) {
	opts := AutostartOptions{
		AppName:   "AnixOps SD-WAN",
		ExecPath:  "/opt/anixops/anix-ui",
		ConfigDir: t.TempDir(),
	}

	obj := renderAutostartSection(opts)
	box, ok := obj.(*fyne.Container)
	if !ok {
		t.Fatalf("expected container, got %T", obj)
	}
	enable := findButtonByText(box, "Enable Start at Login")
	if enable == nil {
		t.Fatal("expected enable button")
	}
	disable := findButtonByText(box, "Disable Start at Login")
	if disable == nil {
		t.Fatal("expected disable button")
	}
	status, ok := box.Objects[4].(*widget.Label)
	if !ok {
		t.Fatalf("expected status label, got %T", box.Objects[4])
	}

	enable.OnTapped()
	if !containsLabelContains(box, "autostart enabled:") {
		t.Fatalf("expected autostart enabled status, got %q", status.Text)
	}
	enabled, path, err := AutostartState(opts)
	if err != nil {
		t.Fatalf("autostart state after enable: %v", err)
	}
	if !enabled || path == "" {
		t.Fatalf("expected enabled autostart state, got enabled=%t path=%s", enabled, path)
	}

	disable.OnTapped()
	if !containsLabelContains(box, "autostart disabled:") {
		t.Fatalf("expected autostart disabled status, got %q", status.Text)
	}
	enabled, path, err = AutostartState(opts)
	if err != nil {
		t.Fatalf("autostart state after disable: %v", err)
	}
	if enabled {
		t.Fatalf("expected disabled autostart state, got enabled=%t path=%s", enabled, path)
	}
}

func TestRenderSettingsApplyButtonUsesAgentClient(t *testing.T) {
	handler := http.NewServeMux()
	handler.HandleFunc("/v1/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var bundle domain.ConfigBundle
		if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if bundle.ID != "cfg-456" || bundle.TenantID != "tenant-b" || bundle.TargetID != "device-b" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if bundle.Version != "v4" || bundle.Values["transport"] != "reality" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(agent.Snapshot{
			TenantID:      "tenant-b",
			DeviceID:      "device-b",
			Platform:      "linux/amd64",
			ConfigVersion: bundle.Version,
			Protocol:      "reality",
			UpdatedAt:     time.Now().UTC(),
		})
	})

	client, err := NewAgentClient("http://agent.test", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Result(), nil
	})})
	if err != nil {
		t.Fatalf("new agent client: %v", err)
	}

	page := DesktopPage{Title: "Settings", Lines: []string{"Desktop UI can apply local config through the agent."}}
	model := ViewModel{
		DeviceID:      "device-b",
		TenantID:      "tenant-b",
		ConfigVersion: "v3",
		Config: domain.ConfigBundle{
			ID:       "cfg-456",
			TenantID: "tenant-b",
			TargetID: "device-b",
			Version:  "v4",
			Values:   map[string]string{"transport": "reality"},
		},
		Link: LinkStatus{
			Protocol:     transport.ProtocolHysteria2,
			UDPAvailable: true,
		},
	}

	obj := renderPage(page, model, client, AutostartOptions{})
	scroll, ok := obj.(*container.Scroll)
	if !ok {
		t.Fatalf("expected scroll container, got %T", obj)
	}
	content, ok := scroll.Content.(*fyne.Container)
	if !ok {
		t.Fatalf("expected inner container, got %T", scroll.Content)
	}
	button := findButtonByText(content, "Apply Config")
	if button == nil {
		t.Fatal("expected settings apply button")
	}
	button.OnTapped()
	if !containsLabelContains(content, "applied config version v4") {
		t.Fatalf("expected settings status to reflect applied config, got UI without status text")
	}
}

func TestRenderProtocolSwitchingApplyButtonUsesAgentClient(t *testing.T) {
	handler := http.NewServeMux()
	handler.HandleFunc("/v1/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var bundle domain.ConfigBundle
		if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if bundle.ID != "cfg-123" || bundle.TenantID != "tenant-a" || bundle.TargetID != "device-a" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if bundle.Version != "v3" || bundle.Values["transport"] != "tuic" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(agent.Snapshot{
			TenantID:      "tenant-a",
			DeviceID:      "device-a",
			Platform:      "linux/amd64",
			ConfigVersion: bundle.Version,
			Protocol:      "tuic",
			UpdatedAt:     time.Now().UTC(),
		})
	})

	client, err := NewAgentClient("http://agent.test", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Result(), nil
	})})
	if err != nil {
		t.Fatalf("new agent client: %v", err)
	}

	page := DesktopPage{Title: "Protocol switching", Lines: []string{"Current entry protocol: hysteria2"}}
	model := ViewModel{
		DeviceID:      "device-a",
		TenantID:      "tenant-a",
		ConfigVersion: "v2",
		Config: domain.ConfigBundle{
			ID:       "cfg-123",
			TenantID: "tenant-a",
			TargetID: "device-a",
			Version:  "v3",
			Values:   map[string]string{"transport": "tuic"},
		},
		Link: LinkStatus{
			Protocol:     transport.ProtocolHysteria2,
			UDPAvailable: true,
		},
	}

	obj := renderPage(page, model, client, AutostartOptions{})
	scroll, ok := obj.(*container.Scroll)
	if !ok {
		t.Fatalf("expected scroll container, got %T", obj)
	}
	content, ok := scroll.Content.(*fyne.Container)
	if !ok {
		t.Fatalf("expected inner container, got %T", scroll.Content)
	}
	button := findButtonByText(content, "Switch Protocol")
	if button == nil {
		t.Fatal("expected switch protocol button")
	}

	button.OnTapped()

	if !containsLabelContains(content, "applied config version v3") {
		t.Fatalf("expected status to reflect applied config, got %q", renderText(content))
	}
}

func TestOverviewCanvasInteractiveWorkflow(t *testing.T) {
	handler := http.NewServeMux()
	handler.HandleFunc("/v1/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var bundle domain.ConfigBundle
		if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(agent.Snapshot{
			TenantID:      bundle.TenantID,
			DeviceID:      bundle.TargetID,
			Platform:      "linux/amd64",
			ConfigVersion: bundle.Version,
			Protocol:      transport.Protocol(bundle.Values["transport"]),
			UpdatedAt:     time.Now().UTC(),
		})
	})

	client, err := NewAgentClient("http://agent.test", &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Result(), nil
	})})
	if err != nil {
		t.Fatalf("new agent client: %v", err)
	}

	model := ViewModel{
		TenantID:      "tenant-a",
		DeviceID:      "device-a",
		Running:       true,
		ConfigVersion: "v1",
		Config: domain.ConfigBundle{
			ID:       "cfg-123",
			TenantID: "tenant-a",
			TargetID: "device-a",
			Version:  "v2",
			Values:   map[string]string{"transport": "tuic"},
		},
		Link: LinkStatus{
			Protocol:     transport.ProtocolHysteria2,
			UDPAvailable: true,
		},
	}
	opts := AutostartOptions{
		AppName:   "AnixOps SD-WAN",
		ExecPath:  "/opt/anixops/anix-ui",
		HomeDir:   t.TempDir(),
		ConfigDir: t.TempDir(),
	}
	content := NewOverviewCanvas(model, client, opts)
	_ = test.NewTempWindow(t, content)

	tabs := findAppTabs(content)
	if tabs == nil {
		t.Fatal("expected overview canvas tabs")
	}

	assertTabInteractive(t, tabs, "Settings", func(page fyne.CanvasObject) {
		button := findButtonByText(page, "Apply Config")
		if button == nil {
			t.Fatal("expected settings apply button")
		}
		test.Tap(button)
		if !containsLabelContains(page, "applied config version v2") {
			t.Fatalf("expected settings page status to update, got %q", renderText(page))
		}

		enable := findButtonByText(page, "Enable Start at Login")
		if enable == nil {
			t.Fatal("expected autostart enable button")
		}
		test.Tap(enable)
		if !containsLabelContains(page, "autostart enabled:") {
			t.Fatalf("expected autostart status update, got %q", renderText(page))
		}
	})

	assertTabInteractive(t, tabs, "Protocol switching", func(page fyne.CanvasObject) {
		button := findButtonByText(page, "Switch Protocol")
		if button == nil {
			t.Fatal("expected protocol switching button")
		}
		test.Tap(button)
		if !containsLabelContains(page, "applied config version v2") {
			t.Fatalf("expected protocol switch status to update, got %q", renderText(page))
		}
	})

	assertTabInteractive(t, tabs, "Diagnostics", func(page fyne.CanvasObject) {
		button := findButtonByText(page, "Run Self-check")
		if button == nil {
			t.Fatal("expected diagnostics self-check button")
		}
		test.Tap(button)
		if !containsLabelContains(page, "Self-check passed") {
			t.Fatalf("expected diagnostics self-check status to update, got %q", renderText(page))
		}
	})
}

func containsLabelText(obj fyne.CanvasObject, text string) bool {
	switch v := obj.(type) {
	case *widget.Label:
		return v.Text == text
	case *container.Scroll:
		return containsLabelText(v.Content, text)
	case *fyne.Container:
		for _, child := range v.Objects {
			if containsLabelText(child, text) {
				return true
			}
		}
	}
	return false
}

func containsLabelContains(obj fyne.CanvasObject, text string) bool {
	switch v := obj.(type) {
	case *widget.Label:
		return strings.Contains(v.Text, text)
	case *container.Scroll:
		return containsLabelContains(v.Content, text)
	case *fyne.Container:
		for _, child := range v.Objects {
			if containsLabelContains(child, text) {
				return true
			}
		}
	}
	return false
}

func findButtonByText(obj fyne.CanvasObject, text string) *widget.Button {
	switch v := obj.(type) {
	case *widget.Button:
		if v.Text == text {
			return v
		}
	case *container.Scroll:
		return findButtonByText(v.Content, text)
	case *fyne.Container:
		for _, child := range v.Objects {
			if button := findButtonByText(child, text); button != nil {
				return button
			}
		}
	}
	return nil
}

func findAppTabs(obj fyne.CanvasObject) *container.AppTabs {
	switch v := obj.(type) {
	case *container.AppTabs:
		return v
	case *container.Scroll:
		return findAppTabs(v.Content)
	case *fyne.Container:
		for _, child := range v.Objects {
			if tabs := findAppTabs(child); tabs != nil {
				return tabs
			}
		}
	}
	return nil
}

func assertTabInteractive(t *testing.T, tabs *container.AppTabs, title string, fn func(page fyne.CanvasObject)) {
	t.Helper()

	for i, item := range tabs.Items {
		if item.Text != title {
			continue
		}
		tabs.SelectIndex(i)
		fn(item.Content)
		return
	}
	t.Fatalf("tab %q not found", title)
}

func renderText(obj fyne.CanvasObject) string {
	switch v := obj.(type) {
	case *widget.Label:
		return v.Text
	case *container.Scroll:
		return renderText(v.Content)
	case *fyne.Container:
		var lines []string
		for _, child := range v.Objects {
			if text := renderText(child); text != "" {
				lines = append(lines, text)
			}
		}
		return strings.Join(lines, " | ")
	}
	return ""
}
