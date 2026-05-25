package linuxgw

import (
	"context"

	"anixops-sd-wan/internal/policy"
	"anixops-sd-wan/internal/system"
)

func ApplyObservedPolicyRoutes(ctx context.Context, base Config, observations []policy.Request, classifier *policy.Classifier, rules []policy.Rule, targets []EgressRouteTarget, planOptions PolicyRoutePlanOptions, paths ApplyPaths, runner system.Runner, writer system.Writer) ([]RouteRule, error) {
	planned, err := PlanObservedPolicyRouteRules(observations, classifier, rules, targets, planOptions)
	if err != nil {
		return nil, err
	}
	next := base
	next.RouteRules = append(append([]RouteRule(nil), base.RouteRules...), planned...)
	if err := next.ApplyWithRollback(ctx, paths, runner, writer); err != nil {
		return planned, err
	}
	return planned, nil
}
