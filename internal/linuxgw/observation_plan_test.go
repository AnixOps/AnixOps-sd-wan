package linuxgw

import (
	"strings"
	"testing"

	"anixops-sd-wan/internal/policy"
)

func TestPlanObservedPolicyRouteRulesMarksClassifiedDomainTraffic(t *testing.T) {
	classifier, err := policy.NewClassifier([]policy.ClassificationRule{{
		ID:           "ai-domain",
		Priority:     100,
		DomainSuffix: "openai.com",
		Class:        policy.ClassAI,
	}})
	if err != nil {
		t.Fatalf("new classifier: %v", err)
	}

	rules, err := PlanObservedPolicyRouteRules([]policy.Request{{
		TenantID: "tenant-a",
		Domain:   "api.openai.com",
		IP:       "203.0.113.10",
	}}, classifier, []policy.Rule{{
		ID:           "ai-egress",
		TenantID:     "tenant-a",
		Priority:     100,
		Class:        policy.ClassAI,
		EgressNodeID: "egress-ai",
	}}, []EgressRouteTarget{{
		NodeID:    "egress-ai",
		Gateway:   "10.0.0.2",
		Interface: "wg-ai",
		Table:     202,
	}}, PolicyRoutePlanOptions{
		MarkBase:       300,
		PreferenceBase: 13000,
	})
	if err != nil {
		t.Fatalf("plan observed policy route rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected one observed route rule, got %+v", rules)
	}
	rule := rules[0]
	if rule.MatchCIDR != "203.0.113.10/32" || rule.Mark != 300 || rule.Table != 202 || rule.Preference != 13000 {
		t.Fatalf("unexpected observed route rule: %+v", rule)
	}
	if rule.DestCIDR != "0.0.0.0/0" || rule.Gateway != "10.0.0.2" || rule.Interface != "wg-ai" {
		t.Fatalf("unexpected observed route target fields: %+v", rule)
	}

	config := testConfig()
	config.RouteRules = rules
	rendered, err := config.RenderNftables()
	if err != nil {
		t.Fatalf("render nftables: %v", err)
	}
	if !strings.Contains(rendered, `iifname "lan0" ip daddr 203.0.113.10/32 meta mark set 300`) {
		t.Fatalf("expected observed classified traffic nft mark, got:\n%s", rendered)
	}
}

func TestPlanObservedPolicyRouteRulesDefaultsIPv6RouteDestination(t *testing.T) {
	rules, err := PlanObservedPolicyRouteRules([]policy.Request{{
		TenantID: "tenant-a",
		IP:       "2001:db8::10",
		Class:    policy.ClassEnterprise,
	}}, nil, []policy.Rule{{
		ID:           "enterprise-egress",
		TenantID:     "tenant-a",
		Priority:     100,
		Class:        policy.ClassEnterprise,
		EgressNodeID: "egress-enterprise",
	}}, []EgressRouteTarget{{
		NodeID:    "egress-enterprise",
		Interface: "wg-enterprise",
		Table:     203,
	}}, PolicyRoutePlanOptions{
		MarkBase:       400,
		PreferenceBase: 14000,
	})
	if err != nil {
		t.Fatalf("plan observed ipv6 route rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected one observed ipv6 route rule, got %+v", rules)
	}
	if rules[0].MatchCIDR != "2001:db8::10/128" || rules[0].DestCIDR != "::/0" {
		t.Fatalf("expected ipv6 host match and default route, got %+v", rules[0])
	}

	config := testConfig()
	config.RouteRules = rules
	rendered, err := config.RenderNftables()
	if err != nil {
		t.Fatalf("render nftables: %v", err)
	}
	if !strings.Contains(rendered, `iifname "lan0" ip6 daddr 2001:db8::10/128 meta mark set 400`) {
		t.Fatalf("expected observed ipv6 nft mark, got:\n%s", rendered)
	}
}

func TestPlanObservedPolicyRouteRulesSkipsUnmatchedAndDeduplicates(t *testing.T) {
	rules, err := PlanObservedPolicyRouteRules([]policy.Request{
		{TenantID: "tenant-a", IP: "203.0.113.10", Class: policy.ClassAI},
		{TenantID: "tenant-a", IP: "203.0.113.10", Class: policy.ClassAI},
		{TenantID: "tenant-a", IP: "203.0.113.11", Class: policy.ClassVideo},
	}, nil, []policy.Rule{{
		ID:           "ai-egress",
		TenantID:     "tenant-a",
		Priority:     100,
		Class:        policy.ClassAI,
		EgressNodeID: "egress-ai",
	}}, []EgressRouteTarget{{
		NodeID:    "egress-ai",
		Interface: "wg-ai",
		Table:     202,
	}}, PolicyRoutePlanOptions{})
	if err != nil {
		t.Fatalf("plan observed policy route rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected one deduplicated matched route rule, got %+v", rules)
	}
	if rules[0].MatchCIDR != "203.0.113.10/32" {
		t.Fatalf("unexpected deduplicated match cidr: %+v", rules[0])
	}
}

func TestPlanObservedPolicyRouteRulesRejectsMissingObservedIP(t *testing.T) {
	_, err := PlanObservedPolicyRouteRules([]policy.Request{{
		TenantID: "tenant-a",
		Domain:   "api.openai.com",
	}}, nil, []policy.Rule{{
		ID:           "ai-egress",
		TenantID:     "tenant-a",
		Priority:     100,
		Class:        policy.ClassAI,
		EgressNodeID: "egress-ai",
	}}, []EgressRouteTarget{{
		NodeID:    "egress-ai",
		Interface: "wg-ai",
		Table:     202,
	}}, PolicyRoutePlanOptions{})
	if err == nil {
		t.Fatal("expected missing observed ip to be rejected")
	}
	if !strings.Contains(err.Error(), "ip is required") {
		t.Fatalf("expected missing ip error, got %v", err)
	}
}
