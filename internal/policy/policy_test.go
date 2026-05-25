package policy

import "testing"

func TestEngineMatchesDomainSuffix(t *testing.T) {
	engine, err := NewEngine([]Rule{{
		ID:           "ai-openai",
		TenantID:     "tenant-a",
		Priority:     100,
		DomainSuffix: "openai.com",
		Class:        ClassAI,
		EgressNodeID: "jp-egress-1",
	}})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	decision := engine.Evaluate(Request{TenantID: "tenant-a", Domain: "api.openai.com", Class: ClassAI})
	if !decision.Matched {
		t.Fatal("expected request to match")
	}
	if decision.EgressNodeID != "jp-egress-1" {
		t.Fatalf("expected jp-egress-1, got %s", decision.EgressNodeID)
	}
}

func TestEngineKeepsTenantRulesIsolated(t *testing.T) {
	engine, err := NewEngine([]Rule{{
		ID:           "tenant-a-ai",
		TenantID:     "tenant-a",
		Priority:     100,
		DomainSuffix: "openai.com",
		EgressNodeID: "jp-egress-1",
	}})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	decision := engine.Evaluate(Request{TenantID: "tenant-b", Domain: "api.openai.com"})
	if decision.Matched {
		t.Fatalf("expected tenant-b request not to match tenant-a rule")
	}
}

func TestEngineUsesHighestPriorityRule(t *testing.T) {
	engine, err := NewEngine([]Rule{
		{
			ID:           "low",
			TenantID:     "tenant-a",
			Priority:     10,
			DomainSuffix: "example.com",
			EgressNodeID: "sg-egress",
		},
		{
			ID:           "high",
			TenantID:     "tenant-a",
			Priority:     100,
			DomainSuffix: "example.com",
			EgressNodeID: "hk-egress",
		},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	decision := engine.Evaluate(Request{TenantID: "tenant-a", Domain: "www.example.com"})
	if decision.RuleID != "high" || decision.EgressNodeID != "hk-egress" {
		t.Fatalf("expected high priority rule, got %+v", decision)
	}
}

func TestEngineMatchesIPAndASN(t *testing.T) {
	engine, err := NewEngine([]Rule{
		{
			ID:           "aws-ip",
			TenantID:     "tenant-a",
			Priority:     50,
			IPCIDR:       "203.0.113.0/24",
			EgressNodeID: "us-egress",
		},
		{
			ID:           "asn",
			TenantID:     "tenant-a",
			Priority:     40,
			ASN:          64512,
			EgressNodeID: "eu-egress",
		},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	ipDecision := engine.Evaluate(Request{TenantID: "tenant-a", IP: "203.0.113.10"})
	if ipDecision.EgressNodeID != "us-egress" {
		t.Fatalf("expected us-egress, got %+v", ipDecision)
	}

	asnDecision := engine.Evaluate(Request{TenantID: "tenant-a", ASN: 64512})
	if asnDecision.EgressNodeID != "eu-egress" {
		t.Fatalf("expected eu-egress, got %+v", asnDecision)
	}
}
