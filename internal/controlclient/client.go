package controlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"anixops-sd-wan/internal/auth"
	"anixops-sd-wan/internal/buildinfo"
	"anixops-sd-wan/internal/cert"
	configsign "anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/policy"
	"anixops-sd-wan/internal/telemetry"
)

type Credentials struct {
	TenantID    string
	ActorID     string
	Roles       []auth.Role
	BearerToken string
}

type Client struct {
	baseURL    string
	httpClient *http.Client
	creds      Credentials
}

type AuditQuery struct {
	Action     string
	Actor      string
	ObjectType string
	ObjectID   string
	Since      time.Time
	Until      time.Time
	Limit      int
}

func New(baseURL string, httpClient *http.Client) (*Client, error) {
	return NewWithCredentials(baseURL, httpClient, Credentials{})
}

func NewWithCredentials(baseURL string, httpClient *http.Client, creds Credentials) (*Client, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		return nil, fmt.Errorf("control base url is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{baseURL: baseURL, httpClient: httpClient, creds: creds}, nil
}

func NewWithBearer(baseURL string, httpClient *http.Client, token string) (*Client, error) {
	return NewWithCredentials(baseURL, httpClient, Credentials{BearerToken: token})
}

func (c *Client) Healthz(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodGet, "/healthz", nil, http.StatusOK, nil)
}

func (c *Client) Version(ctx context.Context) (buildinfo.Info, error) {
	var info buildinfo.Info
	if err := c.doJSON(ctx, http.MethodGet, "/version", nil, http.StatusOK, &info); err != nil {
		return buildinfo.Info{}, err
	}
	return info, nil
}

func (c *Client) IssueSession(ctx context.Context, ttlHours int) (auth.Session, error) {
	var session auth.Session
	payload := map[string]interface{}{"ttl_hours": ttlHours}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/sessions", payload, http.StatusCreated, &session); err != nil {
		return auth.Session{}, err
	}
	return session, nil
}

func (c *Client) RevokeSession(ctx context.Context) error {
	return c.doJSON(ctx, http.MethodDelete, "/v1/sessions", nil, http.StatusNoContent, nil)
}

func (c *Client) Login(ctx context.Context, tenantID, subjectID, password string, ttlHours int) (auth.Session, error) {
	var session auth.Session
	payload := map[string]interface{}{
		"tenant_id":  tenantID,
		"subject_id": subjectID,
		"password":   password,
		"ttl_hours":  ttlHours,
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/login", payload, http.StatusCreated, &session); err != nil {
		return auth.Session{}, err
	}
	return session, nil
}

func (c *Client) OIDCLogin(ctx context.Context, idToken string, ttlHours int) (auth.Session, error) {
	var session auth.Session
	payload := map[string]interface{}{
		"id_token":  idToken,
		"ttl_hours": ttlHours,
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/oidc-login", payload, http.StatusCreated, &session); err != nil {
		return auth.Session{}, err
	}
	return session, nil
}

func (c *Client) ConfigSigningKey(ctx context.Context) (configsign.SigningPublicKey, error) {
	var key configsign.SigningPublicKey
	if err := c.doJSON(ctx, http.MethodGet, "/v1/config-signing-key", nil, http.StatusOK, &key); err != nil {
		return configsign.SigningPublicKey{}, err
	}
	return key, nil
}

func (c *Client) RotateConfigSigningKey(ctx context.Context) (configsign.SigningPublicKey, error) {
	var key configsign.SigningPublicKey
	if err := c.doJSON(ctx, http.MethodPost, "/v1/config-signing-key", nil, http.StatusOK, &key); err != nil {
		return configsign.SigningPublicKey{}, err
	}
	return key, nil
}

func (c *Client) ConfigSigningKeyApprovalRequest(ctx context.Context) (configsign.SigningKeyApprovalRequest, error) {
	var request configsign.SigningKeyApprovalRequest
	if err := c.doJSON(ctx, http.MethodGet, "/v1/config-signing-key/approval-request", nil, http.StatusOK, &request); err != nil {
		return configsign.SigningKeyApprovalRequest{}, err
	}
	return request, nil
}

func (c *Client) CreateTenant(ctx context.Context, tenant domain.Tenant) (domain.Tenant, error) {
	var created domain.Tenant
	if err := c.doJSON(ctx, http.MethodPost, "/v1/tenants", tenant, http.StatusCreated, &created); err != nil {
		return domain.Tenant{}, err
	}
	return created, nil
}

func (c *Client) RegisterDevice(ctx context.Context, tenantID string, device domain.Device) (domain.Device, error) {
	var created domain.Device
	if err := c.doJSON(ctx, http.MethodPost, tenantPath(tenantID, "devices"), device, http.StatusCreated, &created); err != nil {
		return domain.Device{}, err
	}
	return created, nil
}

func (c *Client) RegisterNode(ctx context.Context, tenantID string, node domain.Node) (domain.Node, error) {
	var created domain.Node
	if err := c.doJSON(ctx, http.MethodPost, tenantPath(tenantID, "nodes"), node, http.StatusCreated, &created); err != nil {
		return domain.Node{}, err
	}
	return created, nil
}

func (c *Client) PushNodeHeartbeat(ctx context.Context, tenantID string, heartbeat domain.NodeHeartbeat) (domain.Node, error) {
	var updated domain.Node
	if err := c.doJSON(ctx, http.MethodPost, tenantPath(tenantID, "node-heartbeats"), heartbeat, http.StatusOK, &updated); err != nil {
		return domain.Node{}, err
	}
	return updated, nil
}

func (c *Client) RetireNode(ctx context.Context, tenantID, nodeID string) (domain.Node, error) {
	var retired domain.Node
	payload := map[string]string{"node_id": nodeID}
	if err := c.doJSON(ctx, http.MethodPost, tenantPath(tenantID, "node-retirements"), payload, http.StatusOK, &retired); err != nil {
		return domain.Node{}, err
	}
	return retired, nil
}

func (c *Client) Inventory(ctx context.Context, tenantID string) (domain.Inventory, error) {
	var inventory domain.Inventory
	if err := c.doJSON(ctx, http.MethodGet, tenantPath(tenantID, "inventory"), nil, http.StatusOK, &inventory); err != nil {
		return domain.Inventory{}, err
	}
	return inventory, nil
}

func (c *Client) AuditEvents(ctx context.Context, tenantID string, query AuditQuery) ([]domain.AuditEvent, error) {
	values := url.Values{}
	if query.Action != "" {
		values.Set("action", query.Action)
	}
	if query.Actor != "" {
		values.Set("actor", query.Actor)
	}
	if query.ObjectType != "" {
		values.Set("object_type", query.ObjectType)
	}
	if query.ObjectID != "" {
		values.Set("object_id", query.ObjectID)
	}
	if !query.Since.IsZero() {
		values.Set("since", query.Since.Format(time.RFC3339Nano))
	}
	if !query.Until.IsZero() {
		values.Set("until", query.Until.Format(time.RFC3339Nano))
	}
	if query.Limit > 0 {
		values.Set("limit", strconv.Itoa(query.Limit))
	}
	path := tenantPath(tenantID, "audit")
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var events []domain.AuditEvent
	if err := c.doJSON(ctx, http.MethodGet, path, nil, http.StatusOK, &events); err != nil {
		return nil, err
	}
	return events, nil
}

func (c *Client) Configs(ctx context.Context, tenantID string) ([]domain.ConfigBundle, error) {
	var configs []domain.ConfigBundle
	if err := c.doJSON(ctx, http.MethodGet, tenantPath(tenantID, "configs"), nil, http.StatusOK, &configs); err != nil {
		return nil, err
	}
	return configs, nil
}

func (c *Client) WatchConfig(ctx context.Context, tenantID, targetID, sinceVersion string, timeout time.Duration) (domain.ConfigBundle, bool, error) {
	targetID = strings.TrimSpace(targetID)
	if targetID == "" {
		return domain.ConfigBundle{}, false, fmt.Errorf("config watch target id is required")
	}
	query := url.Values{}
	query.Set("target_id", targetID)
	if sinceVersion != "" {
		query.Set("since_version", sinceVersion)
	}
	if timeout > 0 {
		query.Set("timeout_ms", strconv.FormatInt(timeout.Milliseconds(), 10))
	}
	path := tenantPath(tenantID, "config-watch") + "?" + query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return domain.ConfigBundle{}, false, fmt.Errorf("create request: %w", err)
	}
	c.setAuthHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return domain.ConfigBundle{}, false, fmt.Errorf("control request %s %s: %w", http.MethodGet, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return domain.ConfigBundle{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		var problem map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&problem)
		if problem["error"] != "" {
			return domain.ConfigBundle{}, false, fmt.Errorf("control request %s %s returned %d: %s", http.MethodGet, path, resp.StatusCode, problem["error"])
		}
		return domain.ConfigBundle{}, false, fmt.Errorf("control request %s %s returned %d", http.MethodGet, path, resp.StatusCode)
	}
	var bundle domain.ConfigBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return domain.ConfigBundle{}, false, fmt.Errorf("decode response: %w", err)
	}
	return bundle, true, nil
}

func (c *Client) SignedConfigs(ctx context.Context, tenantID string) ([]configsign.SignedBundle, error) {
	var configs []configsign.SignedBundle
	if err := c.doJSON(ctx, http.MethodGet, tenantPath(tenantID, "signed-configs"), nil, http.StatusOK, &configs); err != nil {
		return nil, err
	}
	return configs, nil
}

func (c *Client) WatchSignedConfig(ctx context.Context, tenantID, targetID, sinceVersion string, timeout time.Duration) (configsign.SignedBundle, bool, error) {
	targetID = strings.TrimSpace(targetID)
	if targetID == "" {
		return configsign.SignedBundle{}, false, fmt.Errorf("signed config watch target id is required")
	}
	query := url.Values{}
	query.Set("target_id", targetID)
	if sinceVersion != "" {
		query.Set("since_version", sinceVersion)
	}
	if timeout > 0 {
		query.Set("timeout_ms", strconv.FormatInt(timeout.Milliseconds(), 10))
	}
	path := tenantPath(tenantID, "signed-config-watch") + "?" + query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return configsign.SignedBundle{}, false, fmt.Errorf("create request: %w", err)
	}
	c.setAuthHeaders(req)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return configsign.SignedBundle{}, false, fmt.Errorf("control request %s %s: %w", http.MethodGet, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return configsign.SignedBundle{}, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		var problem map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&problem)
		if problem["error"] != "" {
			return configsign.SignedBundle{}, false, fmt.Errorf("control request %s %s returned %d: %s", http.MethodGet, path, resp.StatusCode, problem["error"])
		}
		return configsign.SignedBundle{}, false, fmt.Errorf("control request %s %s returned %d", http.MethodGet, path, resp.StatusCode)
	}
	var bundle configsign.SignedBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return configsign.SignedBundle{}, false, fmt.Errorf("decode response: %w", err)
	}
	return bundle, true, nil
}

func (c *Client) UpsertConfig(ctx context.Context, tenantID string, bundle domain.ConfigBundle) (domain.ConfigBundle, error) {
	var created domain.ConfigBundle
	if err := c.doJSON(ctx, http.MethodPost, tenantPath(tenantID, "configs"), bundle, http.StatusCreated, &created); err != nil {
		return domain.ConfigBundle{}, err
	}
	return created, nil
}

func (c *Client) PushTelemetry(ctx context.Context, tenantID string, report telemetry.Report) (telemetry.Report, error) {
	var created telemetry.Report
	if err := c.doJSON(ctx, http.MethodPost, tenantPath(tenantID, "telemetry"), report, http.StatusCreated, &created); err != nil {
		return telemetry.Report{}, err
	}
	return created, nil
}

func (c *Client) Telemetry(ctx context.Context, tenantID string) ([]telemetry.Report, error) {
	var reports []telemetry.Report
	if err := c.doJSON(ctx, http.MethodGet, tenantPath(tenantID, "telemetry"), nil, http.StatusOK, &reports); err != nil {
		return nil, err
	}
	return reports, nil
}

func (c *Client) PolicyDecision(ctx context.Context, tenantID string, request policy.Request) (policy.Decision, error) {
	var decision policy.Decision
	if err := c.doJSON(ctx, http.MethodPost, tenantPath(tenantID, "policy-decisions"), request, http.StatusOK, &decision); err != nil {
		return policy.Decision{}, err
	}
	return decision, nil
}

func (c *Client) UpsertPolicyRule(ctx context.Context, tenantID string, rule policy.Rule) (policy.Rule, error) {
	var created policy.Rule
	if err := c.doJSON(ctx, http.MethodPost, tenantPath(tenantID, "policies"), rule, http.StatusCreated, &created); err != nil {
		return policy.Rule{}, err
	}
	return created, nil
}

func (c *Client) PolicyRules(ctx context.Context, tenantID string) ([]policy.Rule, error) {
	var rules []policy.Rule
	if err := c.doJSON(ctx, http.MethodGet, tenantPath(tenantID, "policies"), nil, http.StatusOK, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func (c *Client) IssueCertificate(ctx context.Context, tenantID, deviceID, role string, ttlHours int) (cert.Issued, error) {
	var issued cert.Issued
	payload := map[string]interface{}{
		"device_id": deviceID,
		"role":      role,
		"ttl_hours": ttlHours,
	}
	if err := c.doJSON(ctx, http.MethodPost, tenantPath(tenantID, "certificates"), payload, http.StatusCreated, &issued); err != nil {
		return cert.Issued{}, err
	}
	return issued, nil
}

func (c *Client) Certificates(ctx context.Context, tenantID string) ([]cert.Record, error) {
	var records []cert.Record
	if err := c.doJSON(ctx, http.MethodGet, tenantPath(tenantID, "certificates"), nil, http.StatusOK, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func (c *Client) RotateCertificate(ctx context.Context, tenantID, serial string, ttlHours int) (cert.Issued, error) {
	var issued cert.Issued
	payload := map[string]interface{}{
		"serial":    serial,
		"ttl_hours": ttlHours,
	}
	if err := c.doJSON(ctx, http.MethodPost, tenantPath(tenantID, "certificate-rotations"), payload, http.StatusCreated, &issued); err != nil {
		return cert.Issued{}, err
	}
	return issued, nil
}

func (c *Client) RevokeCertificate(ctx context.Context, tenantID, serial string) (cert.Record, error) {
	var record cert.Record
	payload := map[string]interface{}{
		"serial": serial,
	}
	if err := c.doJSON(ctx, http.MethodPost, tenantPath(tenantID, "certificate-revocations"), payload, http.StatusOK, &record); err != nil {
		return cert.Record{}, err
	}
	return record, nil
}

func (c *Client) RevokedCertificates(ctx context.Context, tenantID string) ([]cert.Record, error) {
	var records []cert.Record
	if err := c.doJSON(ctx, http.MethodGet, tenantPath(tenantID, "certificate-revocations"), nil, http.StatusOK, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func (c *Client) CertificateRevocationList(ctx context.Context, tenantID string) (cert.RevocationList, error) {
	var list cert.RevocationList
	if err := c.doJSON(ctx, http.MethodGet, tenantPath(tenantID, "certificate-revocation-list"), nil, http.StatusOK, &list); err != nil {
		return cert.RevocationList{}, err
	}
	return list, nil
}

func (c *Client) CertificateStatus(ctx context.Context, tenantID, serial string) (cert.CertificateStatus, error) {
	var status cert.CertificateStatus
	query := url.Values{}
	query.Set("serial", serial)
	if err := c.doJSON(ctx, http.MethodGet, tenantPath(tenantID, "certificate-status")+"?"+query.Encode(), nil, http.StatusOK, &status); err != nil {
		return cert.CertificateStatus{}, err
	}
	return status, nil
}

func (c *Client) CertificateOCSP(ctx context.Context, tenantID string, requestDER []byte) ([]byte, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+tenantPath(tenantID, "certificate-ocsp"), bytes.NewReader(requestDER))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("control request POST %s: %w", tenantPath(tenantID, "certificate-ocsp"), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var problem map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&problem)
		if problem["error"] != "" {
			return nil, fmt.Errorf("control request POST %s returned %d: %s", tenantPath(tenantID, "certificate-ocsp"), resp.StatusCode, problem["error"])
		}
		return nil, fmt.Errorf("control request POST %s returned %d", tenantPath(tenantID, "certificate-ocsp"), resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/ocsp-response" {
		return nil, fmt.Errorf("unexpected ocsp response content type %q", got)
	}
	return io.ReadAll(resp.Body)
}

func (c *Client) doJSON(ctx context.Context, method, path string, payload interface{}, wantStatus int, out interface{}) error {
	var body *bytes.Reader
	if payload == nil {
		body = bytes.NewReader(nil)
	} else {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("control request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != wantStatus {
		var problem map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&problem)
		if problem["error"] != "" {
			return fmt.Errorf("control request %s %s returned %d: %s", method, path, resp.StatusCode, problem["error"])
		}
		return fmt.Errorf("control request %s %s returned %d", method, path, resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func (c *Client) setAuthHeaders(req *http.Request) {
	if c.creds.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.creds.BearerToken)
		return
	}
	if c.creds.TenantID == "" && c.creds.ActorID == "" && len(c.creds.Roles) == 0 {
		return
	}
	req.Header.Set("X-Tenant-ID", c.creds.TenantID)
	req.Header.Set("X-Actor-ID", c.creds.ActorID)
	roles := make([]string, 0, len(c.creds.Roles))
	for _, role := range c.creds.Roles {
		roles = append(roles, string(role))
	}
	req.Header.Set("X-Roles", strings.Join(roles, ","))
}

func tenantPath(tenantID, resource string) string {
	return "/v1/tenants/" + tenantID + "/" + resource
}
