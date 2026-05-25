package core

import (
	"context"
	"fmt"

	"anixops-sd-wan/internal/system"
)

func (n WireGuardNode) Apply(ctx context.Context, interfaceName, configPath string, runner system.Runner, writer system.Writer) error {
	if interfaceName == "" {
		return fmt.Errorf("wireguard interface name is required")
	}
	if configPath == "" {
		return fmt.Errorf("wireguard config path is required")
	}
	if runner == nil {
		return fmt.Errorf("runner is required")
	}
	if writer == nil {
		return fmt.Errorf("writer is required")
	}

	rendered, err := n.RenderConfig()
	if err != nil {
		return err
	}
	if err := writer.WriteFile(configPath, []byte(rendered), 0o600); err != nil {
		return fmt.Errorf("write wireguard config: %w", err)
	}
	if err := runner.Run(ctx, "wg", "setconf", interfaceName, configPath); err != nil {
		return fmt.Errorf("apply wireguard config: %w", err)
	}
	return nil
}

func (c FRRConfig) Apply(ctx context.Context, configPath string, runner system.Runner, writer system.Writer) error {
	if configPath == "" {
		return fmt.Errorf("frr config path is required")
	}
	if runner == nil {
		return fmt.Errorf("runner is required")
	}
	if writer == nil {
		return fmt.Errorf("writer is required")
	}

	rendered, err := c.Render()
	if err != nil {
		return err
	}
	if err := writer.WriteFile(configPath, []byte(rendered), 0o640); err != nil {
		return fmt.Errorf("write frr config: %w", err)
	}
	if err := runner.Run(ctx, "vtysh", "-f", configPath); err != nil {
		return fmt.Errorf("apply frr config: %w", err)
	}
	return nil
}
