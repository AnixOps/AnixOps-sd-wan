package policy

import (
	"fmt"
	"sort"
	"strings"
)

var defaultClassPriorities = map[TrafficClass]int{
	ClassAI:         900,
	ClassEnterprise: 800,
	ClassVideo:      700,
	ClassDomestic:   600,
	ClassDefault:    100,
}

func DefaultClassRules(tenantID string, egressByClass map[TrafficClass]string) ([]Rule, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, fmt.Errorf("tenant id is required")
	}
	required := []TrafficClass{ClassAI, ClassEnterprise, ClassVideo, ClassDomestic, ClassDefault}
	rules := make([]Rule, 0, len(required))
	for _, class := range required {
		egress := strings.TrimSpace(egressByClass[class])
		if egress == "" {
			return nil, fmt.Errorf("egress node for class %q is required", class)
		}
		rule := Rule{
			ID:           "builtin-" + string(class),
			TenantID:     tenantID,
			Priority:     defaultClassPriorities[class],
			Class:        class,
			EgressNodeID: egress,
		}
		if err := rule.Validate(); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func MergeRules(base []Rule, updates []Rule) ([]Rule, error) {
	merged := make(map[string]Rule, len(base)+len(updates))
	for _, rule := range base {
		if err := rule.Validate(); err != nil {
			return nil, err
		}
		merged[rule.ID] = rule
	}
	for _, rule := range updates {
		if err := rule.Validate(); err != nil {
			return nil, err
		}
		merged[rule.ID] = rule
	}

	rules := make([]Rule, 0, len(merged))
	for _, rule := range merged {
		rules = append(rules, rule)
	}
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority == rules[j].Priority {
			return rules[i].ID < rules[j].ID
		}
		return rules[i].Priority > rules[j].Priority
	})
	return rules, nil
}
