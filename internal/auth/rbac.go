package auth

import "fmt"

type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
	RoleAgent    Role = "agent"
)

type Action string

const (
	ActionRead           Action = "read"
	ActionManage         Action = "manage"
	ActionAuditRead      Action = "audit.read"
	ActionCertManage     Action = "cert.manage"
	ActionPolicyEdit     Action = "policy.edit"
	ActionConfigRead     Action = "config.read"
	ActionTelemetryWrite Action = "telemetry.write"
)

type Subject struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Roles    []Role `json:"roles"`
}

type Request struct {
	TenantID string
	Action   Action
}

type Authorizer struct {
	grants map[Role]map[Action]bool
}

func NewAuthorizer() Authorizer {
	return Authorizer{grants: map[Role]map[Action]bool{
		RoleAdmin: {
			ActionRead:           true,
			ActionManage:         true,
			ActionAuditRead:      true,
			ActionCertManage:     true,
			ActionPolicyEdit:     true,
			ActionConfigRead:     true,
			ActionTelemetryWrite: true,
		},
		RoleOperator: {
			ActionRead:           true,
			ActionManage:         true,
			ActionCertManage:     true,
			ActionPolicyEdit:     true,
			ActionConfigRead:     true,
			ActionTelemetryWrite: true,
		},
		RoleViewer: {
			ActionRead:      true,
			ActionAuditRead: true,
		},
		RoleAgent: {
			ActionConfigRead:     true,
			ActionTelemetryWrite: true,
		},
	}}
}

func (a Authorizer) Allowed(subject Subject, request Request) (bool, error) {
	if subject.ID == "" {
		return false, fmt.Errorf("subject id is required")
	}
	if subject.TenantID == "" {
		return false, fmt.Errorf("subject tenant id is required")
	}
	if request.TenantID == "" {
		return false, fmt.Errorf("request tenant id is required")
	}
	if request.Action == "" {
		return false, fmt.Errorf("request action is required")
	}
	if subject.TenantID != request.TenantID {
		return false, nil
	}
	for _, role := range subject.Roles {
		if a.grants[role][request.Action] {
			return true, nil
		}
	}
	return false, nil
}
