package desktop

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"anixops-sd-wan/internal/agent"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/telemetry"
	"anixops-sd-wan/internal/transport"
)

type AgentClient struct {
	baseURL    string
	httpClient *http.Client
}

func NewAgentClient(baseURL string, httpClient *http.Client) (*AgentClient, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, fmt.Errorf("agent base url is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &AgentClient{baseURL: baseURL, httpClient: httpClient}, nil
}

func (c *AgentClient) Snapshot(ctx context.Context) (agent.Snapshot, error) {
	var snapshot agent.Snapshot
	if err := c.getJSON(ctx, "/v1/snapshot", &snapshot); err != nil {
		return agent.Snapshot{}, err
	}
	return snapshot, nil
}

func (c *AgentClient) ViewModel(ctx context.Context) (ViewModel, error) {
	snapshot, err := c.Snapshot(ctx)
	if err != nil {
		return ViewModel{}, err
	}
	model, err := NewViewModel(snapshot, LinkStatus{
		LinkClass:     nonEmptyLinkClass(snapshot.LinkClass),
		Protocol:      snapshot.Protocol,
		RTTMillis:     snapshot.RTTMillis,
		PacketLossPpm: snapshot.PacketLossPermil,
		JitterMillis:  snapshot.JitterMillis,
		UDPAvailable:  snapshot.UDPAvailable,
	}, CertificateStatus{}, nil)
	if err != nil {
		return ViewModel{}, err
	}
	if bundle, err := c.Config(ctx); err == nil {
		model.Config = bundle
	}
	report, err := c.Telemetry(ctx)
	if err != nil {
		model.LogSummary = []string{fmt.Sprintf("telemetry unavailable: %v", err)}
		return model, nil
	}
	model.LogSummary = summarizeTelemetryLogs(report.Logs)
	return model, nil
}

func nonEmptyLinkClass(linkClass transport.LinkClass) transport.LinkClass {
	if linkClass == "" {
		return transport.LinkUnknown
	}
	return linkClass
}

func (c *AgentClient) Telemetry(ctx context.Context) (telemetry.Report, error) {
	var report telemetry.Report
	if err := c.getJSON(ctx, "/v1/telemetry", &report); err != nil {
		return telemetry.Report{}, err
	}
	return report, nil
}

func (c *AgentClient) Config(ctx context.Context) (domain.ConfigBundle, error) {
	var bundle domain.ConfigBundle
	if err := c.getJSON(ctx, "/v1/config", &bundle); err != nil {
		return domain.ConfigBundle{}, err
	}
	return bundle, nil
}

func (c *AgentClient) ApplyConfig(ctx context.Context, bundle domain.ConfigBundle) (agent.Snapshot, error) {
	var snapshot agent.Snapshot
	if err := c.postJSON(ctx, "/v1/config", bundle, &snapshot); err != nil {
		return agent.Snapshot{}, err
	}
	return snapshot, nil
}

func (c *AgentClient) getJSON(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agent request %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent request %s returned %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func (c *AgentClient) postJSON(ctx context.Context, path string, body interface{}, out interface{}) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agent request %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent request %s returned %d", path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func summarizeTelemetryLogs(logs []telemetry.LogRecord) []string {
	summaries := make([]string, 0, len(logs))
	for _, log := range logs {
		level := strings.TrimSpace(log.Level)
		message := strings.TrimSpace(log.Message)
		switch {
		case level == "" && message == "":
			continue
		case level == "":
			summaries = append(summaries, message)
		case message == "":
			summaries = append(summaries, level)
		default:
			summaries = append(summaries, fmt.Sprintf("%s: %s", level, message))
		}
	}
	return summaries
}
