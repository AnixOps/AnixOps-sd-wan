package linuxgw

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"anixops-sd-wan/internal/policy"
)

func PlanObservedPolicyRouteRules(observations []policy.Request, classifier *policy.Classifier, rules []policy.Rule, targets []EgressRouteTarget, options PolicyRoutePlanOptions) ([]RouteRule, error) {
	rawDestCIDR := strings.TrimSpace(options.DestCIDR)
	options, err := normalizePolicyRoutePlanOptions(options)
	if err != nil {
		return nil, err
	}
	byNode, err := egressRouteTargetsByNode(targets)
	if err != nil {
		return nil, err
	}
	engine, err := policy.NewEngine(rules)
	if err != nil {
		return nil, err
	}

	requests := append([]policy.Request(nil), observations...)
	sort.SliceStable(requests, func(i, j int) bool {
		return observedRequestSortKey(requests[i]) < observedRequestSortKey(requests[j])
	})

	var planned []RouteRule
	seen := make(map[string]bool, len(requests))
	for _, request := range requests {
		ip := net.ParseIP(strings.TrimSpace(request.IP))
		if ip == nil {
			return nil, fmt.Errorf("observed traffic ip is required for route marking")
		}
		request.IP = ip.String()
		if classifier != nil {
			request.Class = classifier.Classify(request)
		}
		decision := engine.Evaluate(request)
		if !decision.Matched {
			continue
		}
		target, ok := byNode[strings.TrimSpace(decision.EgressNodeID)]
		if !ok {
			return nil, fmt.Errorf("policy decision %q references unknown egress node %q", decision.RuleID, decision.EgressNodeID)
		}
		matchCIDR := hostCIDR(ip)
		key := decision.RuleID + "|" + matchCIDR + "|" + target.NodeID
		if seen[key] {
			continue
		}
		seen[key] = true

		index := len(planned)
		destCIDR := options.DestCIDR
		if rawDestCIDR == "" && ip.To4() == nil {
			destCIDR = "::/0"
		}
		planned = append(planned, RouteRule{
			Name:       "observed-" + routeRuleNamePart(decision.RuleID) + "-" + routeRuleNamePart(matchCIDR),
			Mark:       options.MarkBase + index,
			MatchCIDR:  matchCIDR,
			Table:      target.Table,
			DestCIDR:   destCIDR,
			Gateway:    target.Gateway,
			Interface:  target.Interface,
			Preference: options.PreferenceBase + index,
		})
	}
	return planned, nil
}

func observedRequestSortKey(request policy.Request) string {
	parts := []string{
		strings.TrimSpace(request.TenantID),
		strings.TrimSpace(request.IP),
		strings.TrimSpace(request.Domain),
		fmt.Sprintf("%010d", request.ASN),
		string(request.Class),
	}
	return strings.Join(parts, "\x00")
}

func hostCIDR(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String() + "/32"
	}
	return ip.String() + "/128"
}

func routeRuleNamePart(value string) string {
	value = strings.TrimSpace(value)
	replacer := strings.NewReplacer(
		"/", "-",
		".", "-",
		":", "-",
		" ", "-",
	)
	value = replacer.Replace(value)
	value = strings.Trim(value, "-")
	if value == "" {
		return "unnamed"
	}
	return value
}
