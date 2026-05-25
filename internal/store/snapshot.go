package store

import (
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/policy"
	"anixops-sd-wan/internal/telemetry"
)

func NewMemoryFromSnapshot(snapshot Snapshot) *Memory {
	memory := NewMemory()
	memory.tenants = copyTenantMap(snapshot.Tenants)
	memory.devices = copyDeviceMap(snapshot.Devices)
	memory.nodes = copyNodeMap(snapshot.Nodes)
	memory.policies = copyPolicyMap(snapshot.Policies)
	memory.configs = copyConfigMap(snapshot.Configs)
	memory.telemetry = copyTelemetryMap(snapshot.Telemetry)
	memory.audit = copyAuditMap(snapshot.Audit)
	return memory
}

func (m *Memory) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return Snapshot{
		Tenants:   copyTenantMap(m.tenants),
		Devices:   copyDeviceMap(m.devices),
		Nodes:     copyNodeMap(m.nodes),
		Policies:  copyPolicyMap(m.policies),
		Configs:   copyConfigMap(m.configs),
		Telemetry: copyTelemetryMap(m.telemetry),
		Audit:     copyAuditMap(m.audit),
	}
}

func copyTenantMap(in map[string]domain.Tenant) map[string]domain.Tenant {
	out := make(map[string]domain.Tenant, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func copyDeviceMap(in map[string]map[string]domain.Device) map[string]map[string]domain.Device {
	out := make(map[string]map[string]domain.Device, len(in))
	for tenantID, devices := range in {
		out[tenantID] = make(map[string]domain.Device, len(devices))
		for id, device := range devices {
			out[tenantID][id] = device
		}
	}
	return out
}

func copyNodeMap(in map[string]map[string]domain.Node) map[string]map[string]domain.Node {
	out := make(map[string]map[string]domain.Node, len(in))
	for tenantID, nodes := range in {
		out[tenantID] = make(map[string]domain.Node, len(nodes))
		for id, node := range nodes {
			out[tenantID][id] = node
		}
	}
	return out
}

func copyPolicyMap(in map[string]map[string]policy.Rule) map[string]map[string]policy.Rule {
	out := make(map[string]map[string]policy.Rule, len(in))
	for tenantID, rules := range in {
		out[tenantID] = make(map[string]policy.Rule, len(rules))
		for id, rule := range rules {
			out[tenantID][id] = rule
		}
	}
	return out
}

func copyConfigMap(in map[string]map[string]domain.ConfigBundle) map[string]map[string]domain.ConfigBundle {
	out := make(map[string]map[string]domain.ConfigBundle, len(in))
	for tenantID, configs := range in {
		out[tenantID] = make(map[string]domain.ConfigBundle, len(configs))
		for id, config := range configs {
			out[tenantID][id] = config
		}
	}
	return out
}

func copyTelemetryMap(in map[string][]telemetry.Report) map[string][]telemetry.Report {
	out := make(map[string][]telemetry.Report, len(in))
	for tenantID, reports := range in {
		out[tenantID] = append([]telemetry.Report(nil), reports...)
	}
	return out
}

func copyAuditMap(in map[string][]domain.AuditEvent) map[string][]domain.AuditEvent {
	out := make(map[string][]domain.AuditEvent, len(in))
	for tenantID, events := range in {
		out[tenantID] = append([]domain.AuditEvent(nil), events...)
	}
	return out
}
