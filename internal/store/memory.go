package store

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/policy"
	"anixops-sd-wan/internal/telemetry"
)

type Memory struct {
	mu        sync.RWMutex
	tenants   map[string]domain.Tenant
	devices   map[string]map[string]domain.Device
	nodes     map[string]map[string]domain.Node
	policies  map[string]map[string]policy.Rule
	configs   map[string]map[string]domain.ConfigBundle
	telemetry map[string][]telemetry.Report
	audit     map[string][]domain.AuditEvent
	now       func() time.Time
}

func NewMemory() *Memory {
	return &Memory{
		tenants:   make(map[string]domain.Tenant),
		devices:   make(map[string]map[string]domain.Device),
		nodes:     make(map[string]map[string]domain.Node),
		policies:  make(map[string]map[string]policy.Rule),
		configs:   make(map[string]map[string]domain.ConfigBundle),
		telemetry: make(map[string][]telemetry.Report),
		audit:     make(map[string][]domain.AuditEvent),
		now:       func() time.Time { return time.Now().UTC() },
	}
}

func (m *Memory) CreateTenant(ctx context.Context, tenant domain.Tenant) (domain.Tenant, error) {
	if err := ctx.Err(); err != nil {
		return domain.Tenant{}, err
	}
	if err := tenant.Validate(); err != nil {
		return domain.Tenant{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tenants[tenant.ID]; exists {
		return domain.Tenant{}, fmt.Errorf("tenant %q already exists", tenant.ID)
	}
	tenant.CreatedAt = m.now()
	m.tenants[tenant.ID] = tenant
	m.auditLocked(tenant.ID, "system", "tenant.create", "tenant", tenant.ID, "")
	return tenant, nil
}

func (m *Memory) RegisterDevice(ctx context.Context, device domain.Device) (domain.Device, error) {
	if err := ctx.Err(); err != nil {
		return domain.Device{}, err
	}
	if err := device.Validate(); err != nil {
		return domain.Device{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tenants[device.TenantID]; !exists {
		return domain.Device{}, fmt.Errorf("tenant %q not found", device.TenantID)
	}
	if m.devices[device.TenantID] == nil {
		m.devices[device.TenantID] = make(map[string]domain.Device)
	}
	now := m.now()
	device.CreatedAt = now
	device.UpdatedAt = now
	if device.Status == "" {
		device.Status = "registered"
	}
	if device.ConfigVersion == "" {
		device.ConfigVersion = "initial"
	}
	m.devices[device.TenantID][device.ID] = device
	m.auditLocked(device.TenantID, device.ID, "device.register", "device", device.ID, "")
	return device, nil
}

func (m *Memory) RegisterNode(ctx context.Context, node domain.Node) (domain.Node, error) {
	if err := ctx.Err(); err != nil {
		return domain.Node{}, err
	}
	if err := node.Validate(); err != nil {
		return domain.Node{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tenants[node.TenantID]; !exists {
		return domain.Node{}, fmt.Errorf("tenant %q not found", node.TenantID)
	}
	if m.nodes[node.TenantID] == nil {
		m.nodes[node.TenantID] = make(map[string]domain.Node)
	}
	now := m.now()
	node.CreatedAt = now
	node.UpdatedAt = now
	m.nodes[node.TenantID][node.ID] = node
	m.auditLocked(node.TenantID, node.ID, "node.register", "node", node.ID, "")
	return node, nil
}

func (m *Memory) RecordNodeHeartbeat(ctx context.Context, heartbeat domain.NodeHeartbeat) (domain.Node, error) {
	if err := ctx.Err(); err != nil {
		return domain.Node{}, err
	}
	if err := heartbeat.Validate(); err != nil {
		return domain.Node{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tenants[heartbeat.TenantID]; !exists {
		return domain.Node{}, fmt.Errorf("tenant %q not found", heartbeat.TenantID)
	}
	node, exists := m.nodes[heartbeat.TenantID][heartbeat.NodeID]
	if !exists {
		return domain.Node{}, fmt.Errorf("node %q not found", heartbeat.NodeID)
	}
	node.Healthy = heartbeat.Healthy
	if heartbeat.Endpoint != "" {
		node.Endpoint = heartbeat.Endpoint
	}
	node.UpdatedAt = m.now()
	m.nodes[heartbeat.TenantID][heartbeat.NodeID] = node
	m.auditLocked(heartbeat.TenantID, heartbeat.NodeID, "node.heartbeat", "node", heartbeat.NodeID, "")
	return node, nil
}

func (m *Memory) RetireNode(ctx context.Context, tenantID, nodeID string) (domain.Node, error) {
	if err := ctx.Err(); err != nil {
		return domain.Node{}, err
	}
	if tenantID == "" {
		return domain.Node{}, fmt.Errorf("node retirement tenant id is required")
	}
	if nodeID == "" {
		return domain.Node{}, fmt.Errorf("node retirement node id is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tenants[tenantID]; !exists {
		return domain.Node{}, fmt.Errorf("tenant %q not found", tenantID)
	}
	node, exists := m.nodes[tenantID][nodeID]
	if !exists {
		return domain.Node{}, fmt.Errorf("node %q not found", nodeID)
	}
	delete(m.nodes[tenantID], nodeID)
	node.Healthy = false
	node.UpdatedAt = m.now()
	m.auditLocked(tenantID, nodeID, "node.retire", "node", nodeID, "")
	return node, nil
}

func (m *Memory) Inventory(ctx context.Context, tenantID string) (domain.Inventory, error) {
	if err := ctx.Err(); err != nil {
		return domain.Inventory{}, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	tenant, exists := m.tenants[tenantID]
	if !exists {
		return domain.Inventory{}, fmt.Errorf("tenant %q not found", tenantID)
	}

	inventory := domain.Inventory{Tenant: tenant}
	for _, device := range m.devices[tenantID] {
		inventory.Devices = append(inventory.Devices, device)
	}
	for _, node := range m.nodes[tenantID] {
		inventory.Nodes = append(inventory.Nodes, node)
	}
	sort.Slice(inventory.Devices, func(i, j int) bool { return inventory.Devices[i].ID < inventory.Devices[j].ID })
	sort.Slice(inventory.Nodes, func(i, j int) bool { return inventory.Nodes[i].ID < inventory.Nodes[j].ID })
	return inventory, nil
}

func (m *Memory) RecordTelemetry(ctx context.Context, report telemetry.Report) (telemetry.Report, error) {
	if err := ctx.Err(); err != nil {
		return telemetry.Report{}, err
	}
	if err := report.Validate(); err != nil {
		return telemetry.Report{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tenants[report.TenantID]; !exists {
		return telemetry.Report{}, fmt.Errorf("tenant %q not found", report.TenantID)
	}
	clean := report.Sanitized()
	m.telemetry[clean.TenantID] = append(m.telemetry[clean.TenantID], clean)
	m.auditLocked(clean.TenantID, clean.SubjectID, "telemetry.record", string(clean.SubjectKind), clean.SubjectID, "")
	return clean, nil
}

func (m *Memory) UpsertPolicyRule(ctx context.Context, rule policy.Rule) (policy.Rule, error) {
	if err := ctx.Err(); err != nil {
		return policy.Rule{}, err
	}
	if err := rule.Validate(); err != nil {
		return policy.Rule{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tenants[rule.TenantID]; !exists {
		return policy.Rule{}, fmt.Errorf("tenant %q not found", rule.TenantID)
	}
	if m.policies[rule.TenantID] == nil {
		m.policies[rule.TenantID] = make(map[string]policy.Rule)
	}
	m.policies[rule.TenantID][rule.ID] = rule
	m.auditLocked(rule.TenantID, "system", "policy.upsert", "policy_rule", rule.ID, "")
	return rule, nil
}

func (m *Memory) PolicyRules(ctx context.Context, tenantID string) ([]policy.Rule, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, exists := m.tenants[tenantID]; !exists {
		return nil, fmt.Errorf("tenant %q not found", tenantID)
	}
	rules := make([]policy.Rule, 0, len(m.policies[tenantID]))
	for _, rule := range m.policies[tenantID] {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Priority == rules[j].Priority {
			return rules[i].ID < rules[j].ID
		}
		return rules[i].Priority > rules[j].Priority
	})
	return rules, nil
}

func (m *Memory) EvaluatePolicy(ctx context.Context, request policy.Request) (policy.Decision, error) {
	rules, err := m.PolicyRules(ctx, request.TenantID)
	if err != nil {
		return policy.Decision{}, err
	}
	engine, err := policy.NewEngine(rules)
	if err != nil {
		return policy.Decision{}, err
	}
	return engine.Evaluate(request), nil
}

func (m *Memory) UpsertConfig(ctx context.Context, bundle domain.ConfigBundle) (domain.ConfigBundle, error) {
	if err := ctx.Err(); err != nil {
		return domain.ConfigBundle{}, err
	}
	if err := bundle.Validate(); err != nil {
		return domain.ConfigBundle{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tenants[bundle.TenantID]; !exists {
		return domain.ConfigBundle{}, fmt.Errorf("tenant %q not found", bundle.TenantID)
	}
	if m.configs[bundle.TenantID] == nil {
		m.configs[bundle.TenantID] = make(map[string]domain.ConfigBundle)
	}
	bundle.CreatedAt = m.now()
	if bundle.Values == nil {
		bundle.Values = map[string]string{}
	}
	m.configs[bundle.TenantID][bundle.ID] = bundle
	m.auditLocked(bundle.TenantID, "system", "config.upsert", "config_bundle", bundle.ID, "")
	return bundle, nil
}

func (m *Memory) Configs(ctx context.Context, tenantID string) ([]domain.ConfigBundle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, exists := m.tenants[tenantID]; !exists {
		return nil, fmt.Errorf("tenant %q not found", tenantID)
	}
	configs := make([]domain.ConfigBundle, 0, len(m.configs[tenantID]))
	for _, bundle := range m.configs[tenantID] {
		configs = append(configs, bundle)
	}
	sort.Slice(configs, func(i, j int) bool { return configs[i].ID < configs[j].ID })
	return configs, nil
}

func (m *Memory) Telemetry(ctx context.Context, tenantID string) ([]telemetry.Report, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, exists := m.tenants[tenantID]; !exists {
		return nil, fmt.Errorf("tenant %q not found", tenantID)
	}
	reports := append([]telemetry.Report(nil), m.telemetry[tenantID]...)
	return reports, nil
}

func (m *Memory) AuditEvents(ctx context.Context, tenantID string) ([]domain.AuditEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, exists := m.tenants[tenantID]; !exists {
		return nil, fmt.Errorf("tenant %q not found", tenantID)
	}
	events := append([]domain.AuditEvent(nil), m.audit[tenantID]...)
	return events, nil
}

func (m *Memory) RecordAuditEvent(ctx context.Context, event domain.AuditEvent) (domain.AuditEvent, error) {
	if err := ctx.Err(); err != nil {
		return domain.AuditEvent{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if event.ID == "" && event.TenantID != "" {
		event.ID = fmt.Sprintf("%s-%06d", event.TenantID, len(m.audit[event.TenantID])+1)
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = m.now()
	}
	if err := event.Validate(); err != nil {
		return domain.AuditEvent{}, err
	}
	m.audit[event.TenantID] = append(m.audit[event.TenantID], event)
	return event, nil
}

func (m *Memory) auditLocked(tenantID, actor, action, objectType, objectID, message string) {
	event := domain.AuditEvent{
		ID:         fmt.Sprintf("%s-%06d", tenantID, len(m.audit[tenantID])+1),
		TenantID:   tenantID,
		Actor:      actor,
		Action:     action,
		ObjectType: objectType,
		ObjectID:   objectID,
		Message:    message,
		CreatedAt:  m.now(),
	}
	m.audit[tenantID] = append(m.audit[tenantID], event)
}
