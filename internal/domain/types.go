package domain

import (
	"fmt"
	"strings"
	"time"
)

type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

func (t Tenant) Validate() error {
	if strings.TrimSpace(t.ID) == "" {
		return fmt.Errorf("tenant id is required")
	}
	if strings.TrimSpace(t.Name) == "" {
		return fmt.Errorf("tenant name is required")
	}
	return nil
}

type DeviceKind string

const (
	DeviceClient DeviceKind = "client"
	DeviceEdge   DeviceKind = "edge"
	DeviceCore   DeviceKind = "core"
	DeviceEgress DeviceKind = "egress"
)

type Device struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	SiteID        string     `json:"site_id,omitempty"`
	Kind          DeviceKind `json:"kind"`
	Name          string     `json:"name"`
	Platform      string     `json:"platform"`
	Status        string     `json:"status"`
	ConfigVersion string     `json:"config_version"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func (d Device) Validate() error {
	if strings.TrimSpace(d.ID) == "" {
		return fmt.Errorf("device id is required")
	}
	if strings.TrimSpace(d.TenantID) == "" {
		return fmt.Errorf("device tenant id is required")
	}
	if d.Kind == "" {
		return fmt.Errorf("device kind is required")
	}
	if strings.TrimSpace(d.Name) == "" {
		return fmt.Errorf("device name is required")
	}
	return nil
}

type NodeRole string

const (
	NodeChinaEntry   NodeRole = "china-entry"
	NodeOverseasEdge NodeRole = "overseas-edge"
	NodeCore         NodeRole = "core"
	NodeEgress       NodeRole = "egress"
)

type Node struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Role      NodeRole  `json:"role"`
	Region    string    `json:"region"`
	Endpoint  string    `json:"endpoint"`
	Healthy   bool      `json:"healthy"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (n Node) Validate() error {
	if strings.TrimSpace(n.ID) == "" {
		return fmt.Errorf("node id is required")
	}
	if strings.TrimSpace(n.TenantID) == "" {
		return fmt.Errorf("node tenant id is required")
	}
	if n.Role == "" {
		return fmt.Errorf("node role is required")
	}
	if strings.TrimSpace(n.Region) == "" {
		return fmt.Errorf("node region is required")
	}
	return nil
}

type NodeHeartbeat struct {
	TenantID string `json:"tenant_id,omitempty"`
	NodeID   string `json:"node_id"`
	Healthy  bool   `json:"healthy"`
	Endpoint string `json:"endpoint,omitempty"`
}

func (h NodeHeartbeat) Validate() error {
	if strings.TrimSpace(h.TenantID) == "" {
		return fmt.Errorf("node heartbeat tenant id is required")
	}
	if strings.TrimSpace(h.NodeID) == "" {
		return fmt.Errorf("node heartbeat node id is required")
	}
	return nil
}

type AuditEvent struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	ObjectType string    `json:"object_type"`
	ObjectID   string    `json:"object_id"`
	Message    string    `json:"message,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

func (e AuditEvent) Validate() error {
	if strings.TrimSpace(e.ID) == "" {
		return fmt.Errorf("audit id is required")
	}
	if strings.TrimSpace(e.TenantID) == "" {
		return fmt.Errorf("audit tenant id is required")
	}
	if strings.TrimSpace(e.Action) == "" {
		return fmt.Errorf("audit action is required")
	}
	if strings.TrimSpace(e.ObjectType) == "" {
		return fmt.Errorf("audit object type is required")
	}
	if strings.TrimSpace(e.ObjectID) == "" {
		return fmt.Errorf("audit object id is required")
	}
	return nil
}

type Inventory struct {
	Tenant  Tenant   `json:"tenant"`
	Devices []Device `json:"devices"`
	Nodes   []Node   `json:"nodes"`
}

type ConfigBundle struct {
	ID        string            `json:"id"`
	TenantID  string            `json:"tenant_id"`
	TargetID  string            `json:"target_id"`
	Version   string            `json:"version"`
	Values    map[string]string `json:"values"`
	CreatedAt time.Time         `json:"created_at"`
}

func (c ConfigBundle) Validate() error {
	if strings.TrimSpace(c.ID) == "" {
		return fmt.Errorf("config id is required")
	}
	if strings.TrimSpace(c.TenantID) == "" {
		return fmt.Errorf("config tenant id is required")
	}
	if strings.TrimSpace(c.TargetID) == "" {
		return fmt.Errorf("config target id is required")
	}
	if strings.TrimSpace(c.Version) == "" {
		return fmt.Errorf("config version is required")
	}
	return nil
}
