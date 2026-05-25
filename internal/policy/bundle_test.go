package policy

import "testing"

func TestDefaultClassRulesCoverRequiredTrafficClasses(t *testing.T) {
	rules, err := DefaultClassRules("tenant-a", map[TrafficClass]string{
		ClassAI:         "jp-ai",
		ClassEnterprise: "sg-enterprise",
		ClassVideo:      "us-video",
		ClassDomestic:   "cn-domestic",
		ClassDefault:    "hk-default",
	})
	if err != nil {
		t.Fatalf("default class rules: %v", err)
	}
	engine, err := NewEngine(rules)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	cases := map[TrafficClass]string{
		ClassAI:         "jp-ai",
		ClassEnterprise: "sg-enterprise",
		ClassVideo:      "us-video",
		ClassDomestic:   "cn-domestic",
		ClassDefault:    "hk-default",
	}
	for class, wantEgress := range cases {
		decision := engine.Evaluate(Request{TenantID: "tenant-a", Class: class})
		if decision.EgressNodeID != wantEgress {
			t.Fatalf("class %s expected %s, got %+v", class, wantEgress, decision)
		}
	}
}

func TestDefaultClassRulesRequireEveryClassEgress(t *testing.T) {
	_, err := DefaultClassRules("tenant-a", map[TrafficClass]string{
		ClassAI: "jp-ai",
	})
	if err == nil {
		t.Fatal("expected missing egress error")
	}
}

func TestMergeRulesOverridesByIDAndSorts(t *testing.T) {
	base, err := DefaultClassRules("tenant-a", map[TrafficClass]string{
		ClassAI:         "jp-ai",
		ClassEnterprise: "sg-enterprise",
		ClassVideo:      "us-video",
		ClassDomestic:   "cn-domestic",
		ClassDefault:    "hk-default",
	})
	if err != nil {
		t.Fatalf("default class rules: %v", err)
	}
	merged, err := MergeRules(base, []Rule{{
		ID:           "builtin-ai",
		TenantID:     "tenant-a",
		Priority:     1000,
		Class:        ClassAI,
		EgressNodeID: "us-ai",
	}})
	if err != nil {
		t.Fatalf("merge rules: %v", err)
	}
	if merged[0].ID != "builtin-ai" || merged[0].EgressNodeID != "us-ai" {
		t.Fatalf("expected updated builtin-ai first, got %+v", merged[0])
	}
	if len(merged) != len(base) {
		t.Fatalf("expected override without adding rule, got %d rules", len(merged))
	}
}
