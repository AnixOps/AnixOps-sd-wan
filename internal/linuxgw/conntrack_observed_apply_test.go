package linuxgw

import (
	"context"
	"strings"
	"testing"

	"anixops-sd-wan/internal/policy"
)

func TestApplyConntrackObservedPolicyRoutesParsesAndApplies(t *testing.T) {
	base := testConfig()
	base.RouteRules = nil
	runner := &recordingRunner{}
	writer := newRecordingWriter()

	planned, err := ApplyConntrackObservedPolicyRoutes(context.Background(), base, "tenant-a", strings.NewReader(strings.Join([]string{
		`tcp 6 120 src=192.168.10.55 dst=203.0.113.44 sport=53001 dport=443`,
		`udp 17 30 src=10.99.0.10 dst=203.0.113.45 sport=53002 dport=443`,
	}, "\n")), PacketObservationOptions{
		SourceCIDRs: []string{"192.168.10.0/24"},
	}, nil, []policy.Rule{{
		ID:           "packet-egress",
		TenantID:     "tenant-a",
		Priority:     100,
		IPCIDR:       "203.0.113.0/24",
		EgressNodeID: "egress-packet",
	}}, []EgressRouteTarget{{
		NodeID:    "egress-packet",
		Gateway:   "10.0.0.3",
		Interface: "wg-packet",
		Table:     203,
	}}, PolicyRoutePlanOptions{
		MarkBase:       900,
		PreferenceBase: 19000,
	}, ApplyPaths{
		NftablesPath: "/tmp/anixops.nft",
		DNSMasqPath:  "/tmp/anixops-dnsmasq.conf",
	}, runner, writer)
	if err != nil {
		t.Fatalf("apply conntrack observed policy routes: %v", err)
	}
	if len(planned) != 1 || planned[0].MatchCIDR != "203.0.113.44/32" {
		t.Fatalf("unexpected planned route rules: %+v", planned)
	}
	nftables := string(writer.files["/tmp/anixops.nft"])
	if !strings.Contains(nftables, `iifname "lan0" ip daddr 203.0.113.44/32 meta mark set 900`) {
		t.Fatalf("expected conntrack observed nft mark, got:\n%s", nftables)
	}
	got := commandStrings(runner.commands)
	for _, want := range []string{
		"ip rule add fwmark 900 table 203 priority 19000",
		"ip route replace 0.0.0.0/0 via 10.0.0.3 dev wg-packet table 203",
	} {
		if !containsCommand(got, want) {
			t.Fatalf("expected command %q, got %+v", want, got)
		}
	}
}

func TestApplyConntrackObservedPolicyRoutesReturnsParseError(t *testing.T) {
	_, err := ApplyConntrackObservedPolicyRoutes(context.Background(), testConfig(), "tenant-a", strings.NewReader(
		`tcp 6 120 src=192.168.10.55 dst=203.0.113.44 sport=53001 dport=443`,
	), PacketObservationOptions{SourceCIDRs: []string{"not-cidr"}}, nil, nil, nil, PolicyRoutePlanOptions{}, ApplyPaths{}, &recordingRunner{}, newRecordingWriter())
	if err == nil {
		t.Fatal("expected invalid source cidr to be rejected")
	}
}
