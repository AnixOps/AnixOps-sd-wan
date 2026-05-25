package store

import (
	"context"

	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/policy"
	"anixops-sd-wan/internal/telemetry"
)

type Repository interface {
	CreateTenant(context.Context, domain.Tenant) (domain.Tenant, error)
	RegisterDevice(context.Context, domain.Device) (domain.Device, error)
	RegisterNode(context.Context, domain.Node) (domain.Node, error)
	RecordNodeHeartbeat(context.Context, domain.NodeHeartbeat) (domain.Node, error)
	RetireNode(context.Context, string, string) (domain.Node, error)
	Inventory(context.Context, string) (domain.Inventory, error)
	RecordTelemetry(context.Context, telemetry.Report) (telemetry.Report, error)
	Telemetry(context.Context, string) ([]telemetry.Report, error)
	UpsertPolicyRule(context.Context, policy.Rule) (policy.Rule, error)
	PolicyRules(context.Context, string) ([]policy.Rule, error)
	EvaluatePolicy(context.Context, policy.Request) (policy.Decision, error)
	UpsertConfig(context.Context, domain.ConfigBundle) (domain.ConfigBundle, error)
	Configs(context.Context, string) ([]domain.ConfigBundle, error)
	RecordAuditEvent(context.Context, domain.AuditEvent) (domain.AuditEvent, error)
	AuditEvents(context.Context, string) ([]domain.AuditEvent, error)
}

var _ Repository = (*Memory)(nil)
