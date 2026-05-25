package linuxgw

import (
	"context"
	"io"

	"anixops-sd-wan/internal/policy"
	"anixops-sd-wan/internal/system"
)

func ApplyDNSMasqObservedPolicyRoutes(ctx context.Context, base Config, tenantID string, reader io.Reader, classifier *policy.Classifier, rules []policy.Rule, targets []EgressRouteTarget, planOptions PolicyRoutePlanOptions, paths ApplyPaths, runner system.Runner, writer system.Writer) ([]RouteRule, error) {
	observations, err := ParseDNSMasqLogObservations(tenantID, reader)
	if err != nil {
		return nil, err
	}
	return ApplyObservedPolicyRoutes(ctx, base, observations, classifier, rules, targets, planOptions, paths, runner, writer)
}
