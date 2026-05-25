package core

import (
	"context"
	"fmt"
	"strings"

	"anixops-sd-wan/internal/system"
)

func (n WireGuardNode) ApplyLinuxDevice(ctx context.Context, interfaceName, configPath string, runner system.Runner, writer system.Writer) error {
	return n.applyLinuxDevice(ctx, interfaceName, configPath, runner, writer, false)
}

func (n WireGuardNode) ApplyLinuxDeviceWithRollback(ctx context.Context, interfaceName, configPath string, runner system.Runner, writer system.Writer) error {
	return n.applyLinuxDevice(ctx, interfaceName, configPath, runner, writer, true)
}

func RollbackLinuxWireGuardDevice(ctx context.Context, interfaceName string, runner system.Runner) error {
	if runner == nil {
		return fmt.Errorf("runner is required")
	}
	if err := validateLinuxInterfaceName(interfaceName); err != nil {
		return err
	}
	if err := runner.Run(ctx, "ip", "link", "delete", "dev", interfaceName); err != nil {
		return fmt.Errorf("delete wireguard interface %s: %w", interfaceName, err)
	}
	return nil
}

func (n WireGuardNode) applyLinuxDevice(ctx context.Context, interfaceName, configPath string, runner system.Runner, writer system.Writer, rollbackOnError bool) error {
	if err := validateLinuxInterfaceName(interfaceName); err != nil {
		return err
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

	created := false
	if err := runner.Run(ctx, "ip", "link", "add", "dev", interfaceName, "type", "wireguard"); err != nil {
		return fmt.Errorf("create wireguard interface %s: %w", interfaceName, err)
	}
	created = true
	if err := runner.Run(ctx, "wg", "setconf", interfaceName, configPath); err != nil {
		return n.maybeRollbackLinuxDevice(ctx, interfaceName, runner, rollbackOnError, created, fmt.Errorf("apply wireguard config: %w", err))
	}
	if err := runner.Run(ctx, "ip", "address", "replace", n.Address, "dev", interfaceName); err != nil {
		return n.maybeRollbackLinuxDevice(ctx, interfaceName, runner, rollbackOnError, created, fmt.Errorf("configure wireguard address: %w", err))
	}
	if err := runner.Run(ctx, "ip", "link", "set", "up", "dev", interfaceName); err != nil {
		return n.maybeRollbackLinuxDevice(ctx, interfaceName, runner, rollbackOnError, created, fmt.Errorf("bring wireguard interface up: %w", err))
	}
	return nil
}

func (n WireGuardNode) maybeRollbackLinuxDevice(ctx context.Context, interfaceName string, runner system.Runner, rollbackOnError, created bool, applyErr error) error {
	if !rollbackOnError || !created {
		return applyErr
	}
	if rollbackErr := RollbackLinuxWireGuardDevice(ctx, interfaceName, runner); rollbackErr != nil {
		return fmt.Errorf("%w; rollback failed: %v", applyErr, rollbackErr)
	}
	return applyErr
}

func validateLinuxInterfaceName(interfaceName string) error {
	interfaceName = strings.TrimSpace(interfaceName)
	if interfaceName == "" {
		return fmt.Errorf("wireguard interface name is required")
	}
	if len(interfaceName) > 15 {
		return fmt.Errorf("wireguard interface name must be 15 characters or fewer")
	}
	for _, r := range interfaceName {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			continue
		}
		return fmt.Errorf("wireguard interface name %q contains unsupported characters", interfaceName)
	}
	return nil
}
