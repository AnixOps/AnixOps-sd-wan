package linuxgw

import (
	"context"
	"strings"
	"testing"

	"anixops-sd-wan/internal/policy"
)

func TestApplyDNSMasqObservedPolicyRoutesParsesAndApplies(t *testing.T) {
	base := testConfig()
	base.RouteRules = nil
	runner := &recordingRunner{}
	writer := newRecordingWriter()
	classifier, err := policy.NewClassifier([]policy.ClassificationRule{{
		ID:           "ai-domain",
		Priority:     100,
		DomainSuffix: "openai.com",
		Class:        policy.ClassAI,
	}})
	if err != nil {
		t.Fatalf("new classifier: %v", err)
	}

	planned, err := ApplyDNSMasqObservedPolicyRoutes(context.Background(), base, "tenant-a", strings.NewReader(
		`dnsmasq[100]: reply api.openai.com is 203.0.113.10`,
	), classifier, []policy.Rule{{
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
		MarkBase:       700,
		PreferenceBase: 17000,
	}, ApplyPaths{
		NftablesPath: "/tmp/anixops.nft",
		DNSMasqPath:  "/tmp/anixops-dnsmasq.conf",
	}, runner, writer)
	if err != nil {
		t.Fatalf("apply dnsmasq observed policy routes: %v", err)
	}
	if len(planned) != 1 || planned[0].MatchCIDR != "203.0.113.10/32" {
		t.Fatalf("unexpected planned route rules: %+v", planned)
	}
	nftables := string(writer.files["/tmp/anixops.nft"])
	if !strings.Contains(nftables, `iifname "lan0" ip daddr 203.0.113.10/32 meta mark set 700`) {
		t.Fatalf("expected dnsmasq observed nft mark, got:\n%s", nftables)
	}
	got := commandStrings(runner.commands)
	for _, want := range []string{
		"ip rule add fwmark 700 table 202 priority 17000",
		"ip route replace 0.0.0.0/0 via 10.0.0.2 dev wg-ai table 202",
	} {
		if !containsCommand(got, want) {
			t.Fatalf("expected command %q, got %+v", want, got)
		}
	}
}
