package desktop

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"anixops-sd-wan/internal/agent"
	"anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/telemetry"
	"anixops-sd-wan/internal/transport"
)

func TestAgentClientLoadsSnapshot(t *testing.T) {
	svc, err := agent.NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	client, err := NewAgentClient("http://agent.test", handlerClient(svc.LocalHandler()))
	if err != nil {
		t.Fatalf("new agent client: %v", err)
	}
	snapshot, err := client.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snapshot.TenantID != "default" || snapshot.DeviceID != "local-dev" {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
}

func TestAgentClientBuildsViewModel(t *testing.T) {
	svc, err := agent.NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	client, err := NewAgentClient("http://agent.test", handlerClient(svc.LocalHandler()))
	if err != nil {
		t.Fatalf("new agent client: %v", err)
	}
	model, err := client.ViewModel(context.Background())
	if err != nil {
		t.Fatalf("view model: %v", err)
	}
	if model.DeviceID != "local-dev" || model.Link.Protocol != svc.Snapshot().Protocol {
		t.Fatalf("unexpected model: %+v", model)
	}
	if model.Link.LinkClass != transport.LinkUnknown || !model.Link.UDPAvailable {
		t.Fatalf("expected link metrics in model, got %+v", model.Link)
	}
	if model.Config.Version != "dev" || model.Config.TenantID != "default" {
		t.Fatalf("expected config bundle in model, got %+v", model.Config)
	}
}

func TestAgentClientLoadsConfig(t *testing.T) {
	svc, err := agent.NewService(config.Default())
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	client, err := NewAgentClient("http://agent.test", handlerClient(svc.LocalHandler()))
	if err != nil {
		t.Fatalf("new agent client: %v", err)
	}
	bundle, err := client.Config(context.Background())
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if bundle.TenantID != "default" || bundle.TargetID != "local-dev" || bundle.Version != "dev" {
		t.Fatalf("unexpected bundle: %+v", bundle)
	}
}

func TestAgentClientUsesTelemetryLogs(t *testing.T) {
	handler := http.NewServeMux()
	handler.HandleFunc("/v1/snapshot", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(agent.Snapshot{
			TenantID:      "tenant-a",
			DeviceID:      "device-a",
			Platform:      "linux/amd64",
			ConfigVersion: "v2",
			Protocol:      "hysteria2",
			UpdatedAt:     time.Now().UTC(),
		})
	})
	handler.HandleFunc("/v1/telemetry", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(telemetry.Report{
			TenantID:    "tenant-a",
			SubjectID:   "device-a",
			SubjectKind: telemetry.SubjectAgent,
			Logs: []telemetry.LogRecord{
				{Level: "info", Message: "telemetry queued"},
				{Level: "warn", Message: "udp unavailable"},
			},
		})
	})

	client, err := NewAgentClient("http://agent.test", handlerClient(handler))
	if err != nil {
		t.Fatalf("new agent client: %v", err)
	}
	model, err := client.ViewModel(context.Background())
	if err != nil {
		t.Fatalf("view model: %v", err)
	}
	if len(model.LogSummary) != 2 || model.LogSummary[0] != "info: telemetry queued" {
		t.Fatalf("unexpected telemetry summary: %+v", model.LogSummary)
	}
}

func TestAgentClientReportsHTTPFailure(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	client, err := NewAgentClient("http://agent.test", handlerClient(handler))
	if err != nil {
		t.Fatalf("new agent client: %v", err)
	}
	if _, err := client.Snapshot(context.Background()); err == nil {
		t.Fatal("expected snapshot error")
	}
}

func TestAgentClientFallsBackWhenTelemetryIsUnavailable(t *testing.T) {
	handler := http.NewServeMux()
	handler.HandleFunc("/v1/snapshot", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(agent.Snapshot{
			TenantID:      "tenant-a",
			DeviceID:      "device-a",
			Platform:      "linux/amd64",
			ConfigVersion: "v2",
			Protocol:      "hysteria2",
			UpdatedAt:     time.Now().UTC(),
		})
	})
	handler.HandleFunc("/v1/telemetry", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	client, err := NewAgentClient("http://agent.test", handlerClient(handler))
	if err != nil {
		t.Fatalf("new agent client: %v", err)
	}
	model, err := client.ViewModel(context.Background())
	if err != nil {
		t.Fatalf("view model fallback: %v", err)
	}
	if len(model.LogSummary) != 1 || model.LogSummary[0] == "" {
		t.Fatalf("expected fallback telemetry summary, got %+v", model.LogSummary)
	}
}

func TestAgentClientAppliesConfig(t *testing.T) {
	handler := http.NewServeMux()
	handler.HandleFunc("/v1/snapshot", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(agent.Snapshot{
			TenantID:      "tenant-a",
			DeviceID:      "device-a",
			Platform:      "linux/amd64",
			ConfigVersion: "v2",
			Protocol:      "hysteria2",
			UpdatedAt:     time.Now().UTC(),
		})
	})
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
		if bundle.Version != "v3" || bundle.TargetID != "device-a" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(agent.Snapshot{
			TenantID:      "tenant-a",
			DeviceID:      "device-a",
			Platform:      "linux/amd64",
			ConfigVersion: bundle.Version,
			Protocol:      "reality",
			UpdatedAt:     time.Now().UTC(),
		})
	})

	client, err := NewAgentClient("http://agent.test", handlerClient(handler))
	if err != nil {
		t.Fatalf("new agent client: %v", err)
	}
	snapshot, err := client.ApplyConfig(context.Background(), domain.ConfigBundle{
		ID:       "cfg-1",
		TenantID: "tenant-a",
		TargetID: "device-a",
		Version:  "v3",
		Values:   map[string]string{"transport": "reality"},
	})
	if err != nil {
		t.Fatalf("apply config: %v", err)
	}
	if snapshot.ConfigVersion != "v3" || snapshot.Protocol != "reality" {
		t.Fatalf("unexpected snapshot after apply: %+v", snapshot)
	}
}

func handlerClient(handler http.Handler) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Result(), nil
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
