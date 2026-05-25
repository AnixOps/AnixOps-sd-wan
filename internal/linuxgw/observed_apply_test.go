package linuxgw

import (
	"context"
	"errors"
	"strings"
	"testing"

	"anixops-sd-wan/internal/policy"
)

func TestApplyObservedPolicyRoutesWritesMarksAndRouteCommands(t *testing.T) {
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

	planned, err := ApplyObservedPolicyRoutes(context.Background(), base, []policy.Request{{
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
		MarkBase:       600,
		PreferenceBase: 16000,
	}, ApplyPaths{
		NftablesPath: "/tmp/anixops.nft",
		DNSMasqPath:  "/tmp/anixops-dnsmasq.conf",
	}, runner, writer)
	if err != nil {
		t.Fatalf("apply observed policy routes: %v", err)
	}
	if len(planned) != 1 || planned[0].MatchCIDR != "203.0.113.10/32" {
		t.Fatalf("unexpected planned observed routes: %+v", planned)
	}
	nftables := string(writer.files["/tmp/anixops.nft"])
	if !strings.Contains(nftables, `iifname "lan0" ip daddr 203.0.113.10/32 meta mark set 600`) {
		t.Fatalf("expected observed nft mark in written config, got:\n%s", nftables)
	}
	got := commandStrings(runner.commands)
	for _, want := range []string{
		"nft -f /tmp/anixops.nft",
		"ip rule add fwmark 600 table 202 priority 16000",
		"ip route replace 0.0.0.0/0 via 10.0.0.2 dev wg-ai table 202",
		"systemctl reload dnsmasq",
	} {
		if !containsCommand(got, want) {
			t.Fatalf("expected command %q, got %+v", want, got)
		}
	}
}

func TestApplyObservedPolicyRoutesRollsBackOnRouteFailure(t *testing.T) {
	base := testConfig()
	base.RouteRules = nil
	routeErr := errors.New("route failed")
	runner := &recordingRunner{errors: map[string]error{
		"ip route replace 0.0.0.0/0 dev wg-ai table 202": routeErr,
	}}
	writer := newRecordingWriter()

	planned, err := ApplyObservedPolicyRoutes(context.Background(), base, []policy.Request{{
		TenantID: "tenant-a",
		IP:       "203.0.113.10",
		Class:    policy.ClassAI,
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
	}}, PolicyRoutePlanOptions{
		MarkBase:       600,
		PreferenceBase: 16000,
	}, ApplyPaths{
		NftablesPath: "/tmp/anixops.nft",
		DNSMasqPath:  "/tmp/anixops-dnsmasq.conf",
	}, runner, writer)
	if err == nil {
		t.Fatal("expected route failure")
	}
	if !strings.Contains(err.Error(), routeErr.Error()) {
		t.Fatalf("expected route error, got %v", err)
	}
	if len(planned) != 1 {
		t.Fatalf("expected planned route to be returned on apply failure, got %+v", planned)
	}

	got := commandStrings(runner.commands)
	for _, want := range []string{
		"nft delete table inet anixops",
		"ip route del 0.0.0.0/0 dev wg-ai table 202",
		"ip rule del fwmark 600 table 202 priority 16000",
	} {
		if !containsCommand(got, want) {
			t.Fatalf("expected rollback command %q, got %+v", want, got)
		}
	}
}

func containsCommand(commands []string, want string) bool {
	for _, command := range commands {
		if command == want {
			return true
		}
	}
	return false
}
