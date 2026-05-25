package linuxgw

import (
	"context"
	"fmt"
	"strings"

	"anixops-sd-wan/internal/system"
)

type ApplyPaths struct {
	NftablesPath string
	DNSMasqPath  string
}

func (c Config) Apply(ctx context.Context, paths ApplyPaths, runner system.Runner, writer system.Writer) error {
	return c.apply(ctx, paths, runner, writer, false)
}

func (c Config) ApplyWithRollback(ctx context.Context, paths ApplyPaths, runner system.Runner, writer system.Writer) error {
	return c.apply(ctx, paths, runner, writer, true)
}

func (c Config) Rollback(ctx context.Context, runner system.Runner) error {
	if runner == nil {
		return fmt.Errorf("runner is required")
	}
	commands, err := c.RenderRollbackCommands()
	if err != nil {
		return err
	}
	for _, command := range commands {
		if err := runShellFields(ctx, runner, command); err != nil {
			return fmt.Errorf("rollback command %q: %w", command, err)
		}
	}
	return nil
}

func (c Config) apply(ctx context.Context, paths ApplyPaths, runner system.Runner, writer system.Writer, rollbackOnError bool) error {
	if runner == nil {
		return fmt.Errorf("runner is required")
	}
	if writer == nil {
		return fmt.Errorf("writer is required")
	}
	if paths.NftablesPath == "" {
		return fmt.Errorf("nftables path is required")
	}
	if paths.DNSMasqPath == "" {
		return fmt.Errorf("dnsmasq path is required")
	}

	nftables, err := c.RenderNftables()
	if err != nil {
		return err
	}
	dnsmasq, err := c.RenderDNSMasq()
	if err != nil {
		return err
	}
	routeCommands, err := c.RenderIPRouteCommands()
	if err != nil {
		return err
	}

	if err := writer.WriteFile(paths.NftablesPath, []byte(nftables), 0o600); err != nil {
		return fmt.Errorf("write nftables config: %w", err)
	}
	if err := writer.WriteFile(paths.DNSMasqPath, []byte(dnsmasq), 0o600); err != nil {
		return fmt.Errorf("write dnsmasq config: %w", err)
	}
	applied := false
	if err := runner.Run(ctx, "nft", "-f", paths.NftablesPath); err != nil {
		return fmt.Errorf("apply nftables config: %w", err)
	}
	applied = true
	for _, command := range routeCommands {
		if err := runShellFields(ctx, runner, command); err != nil {
			return c.maybeRollback(ctx, runner, rollbackOnError, applied, fmt.Errorf("apply route command %q: %w", command, err))
		}
	}
	if err := runner.Run(ctx, "systemctl", "reload", "dnsmasq"); err != nil {
		return c.maybeRollback(ctx, runner, rollbackOnError, applied, fmt.Errorf("reload dnsmasq: %w", err))
	}
	return nil
}

func (c Config) maybeRollback(ctx context.Context, runner system.Runner, rollbackOnError, applied bool, applyErr error) error {
	if !rollbackOnError || !applied {
		return applyErr
	}
	if rollbackErr := c.Rollback(ctx, runner); rollbackErr != nil {
		return fmt.Errorf("%w; rollback failed: %v", applyErr, rollbackErr)
	}
	return applyErr
}

func runShellFields(ctx context.Context, runner system.Runner, command string) error {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return nil
	}
	return runner.Run(ctx, fields[0], fields[1:]...)
}
