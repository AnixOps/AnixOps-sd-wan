package auth

import "testing"

func TestAuthorizerAllowsAdminManage(t *testing.T) {
	allowed, err := NewAuthorizer().Allowed(Subject{
		ID:       "user-a",
		TenantID: "tenant-a",
		Roles:    []Role{RoleAdmin},
	}, Request{TenantID: "tenant-a", Action: ActionManage})
	if err != nil {
		t.Fatalf("allowed: %v", err)
	}
	if !allowed {
		t.Fatal("expected admin to manage tenant")
	}
}

func TestAuthorizerDeniesCrossTenantAccess(t *testing.T) {
	allowed, err := NewAuthorizer().Allowed(Subject{
		ID:       "user-a",
		TenantID: "tenant-a",
		Roles:    []Role{RoleAdmin},
	}, Request{TenantID: "tenant-b", Action: ActionManage})
	if err != nil {
		t.Fatalf("allowed: %v", err)
	}
	if allowed {
		t.Fatal("expected cross-tenant request to be denied")
	}
}

func TestAuthorizerDeniesViewerPolicyEdit(t *testing.T) {
	allowed, err := NewAuthorizer().Allowed(Subject{
		ID:       "user-a",
		TenantID: "tenant-a",
		Roles:    []Role{RoleViewer},
	}, Request{TenantID: "tenant-a", Action: ActionPolicyEdit})
	if err != nil {
		t.Fatalf("allowed: %v", err)
	}
	if allowed {
		t.Fatal("expected viewer policy edit to be denied")
	}
}

func TestAuthorizerAllowsAgentConfigReadAndTelemetryWriteOnly(t *testing.T) {
	authorizer := NewAuthorizer()
	subject := Subject{
		ID:       "agent-a",
		TenantID: "tenant-a",
		Roles:    []Role{RoleAgent},
	}

	allowed, err := authorizer.Allowed(subject, Request{TenantID: "tenant-a", Action: ActionConfigRead})
	if err != nil {
		t.Fatalf("config read: %v", err)
	}
	if !allowed {
		t.Fatal("expected agent to read config")
	}

	allowed, err = authorizer.Allowed(subject, Request{TenantID: "tenant-a", Action: ActionTelemetryWrite})
	if err != nil {
		t.Fatalf("telemetry write: %v", err)
	}
	if !allowed {
		t.Fatal("expected agent to write telemetry")
	}

	allowed, err = authorizer.Allowed(subject, Request{TenantID: "tenant-a", Action: ActionManage})
	if err != nil {
		t.Fatalf("manage: %v", err)
	}
	if allowed {
		t.Fatal("expected agent to be denied tenant management")
	}
}
