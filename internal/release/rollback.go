package release

import (
	"context"
	"fmt"

	"anixops-sd-wan/internal/system"
)

type RollbackResult struct {
	PreviousVersion string    `json:"previous_version"`
	Commands        []Command `json:"commands"`
}

func ExecuteRollback(ctx context.Context, plan RollbackPlan, runner system.Runner) (RollbackResult, error) {
	if err := plan.Validate(); err != nil {
		return RollbackResult{}, err
	}
	if runner == nil {
		return RollbackResult{}, fmt.Errorf("runner is required")
	}
	result := RollbackResult{
		PreviousVersion: plan.PreviousVersion,
	}
	for _, command := range plan.Commands {
		if err := runner.Run(ctx, command.Name, command.Args...); err != nil {
			return result, fmt.Errorf("execute rollback command %q: %w", command.Name, err)
		}
		result.Commands = append(result.Commands, command)
	}
	return result, nil
}
