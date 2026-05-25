package linuxgw

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"anixops-sd-wan/internal/policy"
)

const (
	DefaultPolicyRouteMarkBase       = 1000
	DefaultPolicyRoutePreferenceBase = 10000
	DefaultPolicyRouteDestCIDR       = "0.0.0.0/0"
)

type EgressRouteTarget struct {
	NodeID    string
	Gateway   string
	Interface string
	Table     int
}

func (t EgressRouteTarget) Validate() error {
	if strings.TrimSpace(t.NodeID) == "" {
		return fmt.Errorf("egress route target node id is required")
	}
	if t.Gateway != "" && net.ParseIP(t.Gateway) == nil {
		return fmt.Errorf("egress route target %q invalid gateway", t.NodeID)
	}
	if strings.TrimSpace(t.Interface) == "" {
		return fmt.Errorf("egress route target %q interface is required", t.NodeID)
	}
	if t.Table <= 0 {
		return fmt.Errorf("egress route target %q table must be positive", t.NodeID)
	}
	return nil
}

type PolicyRoutePlanOptions struct {
	MarkBase       int
	PreferenceBase int
	DestCIDR       string
}

func PlanPolicyRouteRules(rules []policy.Rule, targets []EgressRouteTarget, options PolicyRoutePlanOptions) ([]RouteRule, error) {
	options, err := normalizePolicyRoutePlanOptions(options)
	if err != nil {
		return nil, err
	}
	byNode, err := egressRouteTargetsByNode(targets)
	if err != nil {
		return nil, err
	}

	copied := append([]policy.Rule(nil), rules...)
	for _, rule := range copied {
		if err := rule.Validate(); err != nil {
			return nil, err
		}
		if _, ok := byNode[strings.TrimSpace(rule.EgressNodeID)]; !ok {
			return nil, fmt.Errorf("policy rule %q references unknown egress node %q", rule.ID, rule.EgressNodeID)
		}
	}
	sort.SliceStable(copied, func(i, j int) bool {
		if copied[i].Priority == copied[j].Priority {
			return copied[i].ID < copied[j].ID
		}
		return copied[i].Priority > copied[j].Priority
	})

	planned := make([]RouteRule, 0, len(copied))
	for index, rule := range copied {
		target := byNode[strings.TrimSpace(rule.EgressNodeID)]
		planned = append(planned, RouteRule{
			Name:       "policy-" + rule.ID,
			Mark:       options.MarkBase + index,
			MatchCIDR:  strings.TrimSpace(rule.IPCIDR),
			Table:      target.Table,
			DestCIDR:   options.DestCIDR,
			Gateway:    target.Gateway,
			Interface:  target.Interface,
			Preference: options.PreferenceBase + index,
		})
	}
	return planned, nil
}

func egressRouteTargetsByNode(targets []EgressRouteTarget) (map[string]EgressRouteTarget, error) {
	byNode := make(map[string]EgressRouteTarget, len(targets))
	for _, target := range targets {
		if err := target.Validate(); err != nil {
			return nil, err
		}
		target.NodeID = strings.TrimSpace(target.NodeID)
		target.Interface = strings.TrimSpace(target.Interface)
		if _, exists := byNode[target.NodeID]; exists {
			return nil, fmt.Errorf("duplicate egress route target %s", target.NodeID)
		}
		byNode[target.NodeID] = target
	}
	return byNode, nil
}

func normalizePolicyRoutePlanOptions(options PolicyRoutePlanOptions) (PolicyRoutePlanOptions, error) {
	if options.MarkBase == 0 {
		options.MarkBase = DefaultPolicyRouteMarkBase
	}
	if options.PreferenceBase == 0 {
		options.PreferenceBase = DefaultPolicyRoutePreferenceBase
	}
	if options.DestCIDR == "" {
		options.DestCIDR = DefaultPolicyRouteDestCIDR
	}
	options.DestCIDR = strings.TrimSpace(options.DestCIDR)
	if options.MarkBase <= 0 {
		return PolicyRoutePlanOptions{}, fmt.Errorf("policy route mark base must be positive")
	}
	if options.PreferenceBase <= 0 {
		return PolicyRoutePlanOptions{}, fmt.Errorf("policy route preference base must be positive")
	}
	if _, _, err := net.ParseCIDR(options.DestCIDR); err != nil {
		return PolicyRoutePlanOptions{}, fmt.Errorf("invalid policy route destination: %w", err)
	}
	return options, nil
}
