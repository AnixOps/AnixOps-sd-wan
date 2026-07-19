package linuxgw

import (
	"reflect"
	"strings"
	"testing"

	"anixops-sd-wan/internal/controlcontract"
)

func TestCompileServiceChainPlanBuildsABCDConntrackPlan(t *testing.T) {
	profile := controlcontract.PopProfile{
		ID: "pop-a-profile", PrincipalID: "pop-a",
		Routes: []controlcontract.RoutePolicy{{
			ID: "enterprise",
			Selector: controlcontract.RouteSelector{
				SourceCIDR: "10.10.0.0/16", DestinationCIDR: "203.0.113.0/24",
				Protocol: controlcontract.ProtocolTCP,
				Ports:    &controlcontract.PortRange{Start: 443, End: 443},
			},
			Chain: controlcontract.ServiceChain{
				ID: "a-b-c-d", Hops: []string{"pop-b", "pop-c", "pop-d"},
				ReturnHops: []string{"pop-d", "pop-c", "pop-b"},
			},
		}},
	}
	plan, err := CompileServiceChainPlan(profile,
		[]ServiceChainTransportTarget{{POPID: "pop-b", Gateway: "100.64.0.2", Interface: "easytier0", Table: 4200}},
		ServiceChainCompileOptions{LocalPOPID: "pop-a", IngressInterface: "xfrm0", MarkBase: 4000, PreferenceBase: 14000},
	)
	if err != nil {
		t.Fatalf("compile plan: %v", err)
	}
	if len(plan.Routes) != 1 {
		t.Fatalf("route count = %d, want 1", len(plan.Routes))
	}
	if got := plan.Routes[0]; got.NextPOPID != "pop-b" || got.Mark != 4000 || got.Preference != 14000 || got.ChainID != "a-b-c-d" {
		t.Fatalf("unexpected route: %+v", got)
	}
	if got, want := plan.Routes[0].ReturnHops, []string{"pop-d", "pop-c", "pop-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("return hops = %v, want %v", got, want)
	}

	nft, err := plan.RenderNftables()
	if err != nil {
		t.Fatalf("render nftables: %v", err)
	}
	for _, want := range []string{
		"ct state established,related meta mark set ct mark",
		`iifname "xfrm0" ct mark 0 ip saddr 10.10.0.0/16 ip daddr 203.0.113.0/24 tcp dport 443-443 meta mark set 4000 ct mark set 4000`,
	} {
		if !strings.Contains(nft, want) {
			t.Fatalf("missing %q in:\n%s", want, nft)
		}
	}

	commands, err := plan.RenderIPRouteCommands()
	if err != nil {
		t.Fatalf("render routes: %v", err)
	}
	want := []string{
		"ip route replace 0.0.0.0/0 via 100.64.0.2 dev easytier0 table 4200",
		"ip rule add fwmark 4000 table 4200 priority 14000",
	}
	if !reflect.DeepEqual(want, commands) {
		t.Fatalf("commands got %v, want %v", commands, want)
	}
}

func TestCompileServiceChainPlanRejectsUnknownFirstHopTarget(t *testing.T) {
	profile := serviceChainProfile(controlcontract.RouteSelector{DestinationCIDR: "203.0.113.0/24"}, "pop-missing")
	_, err := CompileServiceChainPlan(profile, serviceChainTargets(), serviceChainOptions())
	assertServiceChainError(t, err, "unknown first hop")
}

func TestCompileServiceChainPlanRejectsLocalFirstHopLoop(t *testing.T) {
	profile := serviceChainProfile(controlcontract.RouteSelector{DestinationCIDR: "203.0.113.0/24"}, "pop-a")
	targets := []ServiceChainTransportTarget{{POPID: "pop-a", Gateway: "100.64.0.1", Interface: "easytier0", Table: 4200}}
	_, err := CompileServiceChainPlan(profile, targets, serviceChainOptions())
	assertServiceChainError(t, err, "local POP")
}

func TestCompileServiceChainPlanRejectsDomainSuffixSelector(t *testing.T) {
	profile := serviceChainProfile(controlcontract.RouteSelector{
		DestinationCIDR: "203.0.113.0/24",
		DomainSuffix:    "example.com",
	}, "pop-b")
	_, err := CompileServiceChainPlan(profile, serviceChainTargets(), serviceChainOptions())
	assertServiceChainError(t, err, "domain suffix")
}

func TestCompileServiceChainPlanRejectsTrafficClassSelector(t *testing.T) {
	profile := serviceChainProfile(controlcontract.RouteSelector{
		DestinationCIDR: "203.0.113.0/24",
		TrafficClass:    "enterprise",
	}, "pop-b")
	_, err := CompileServiceChainPlan(profile, serviceChainTargets(), serviceChainOptions())
	assertServiceChainError(t, err, "traffic class")
}

func TestCompileServiceChainPlanRejectsMixedSelectorFamilies(t *testing.T) {
	profile := serviceChainProfile(controlcontract.RouteSelector{
		SourceCIDR:      "10.10.0.0/16",
		DestinationCIDR: "2001:db8:1::/64",
	}, "pop-b")
	_, err := CompileServiceChainPlan(profile, serviceChainTargets(), serviceChainOptions())
	assertServiceChainError(t, err, "mixed IP families")
}

func TestCompileServiceChainPlanRejectsSelectorWithoutCIDR(t *testing.T) {
	profile := serviceChainProfile(controlcontract.RouteSelector{Protocol: controlcontract.ProtocolTCP}, "pop-b")
	_, err := CompileServiceChainPlan(profile, serviceChainTargets(), serviceChainOptions())
	assertServiceChainError(t, err, "CIDR")
}

func TestCompileServiceChainPlanRejectsDuplicateTargetIDs(t *testing.T) {
	targets := []ServiceChainTransportTarget{
		{POPID: "pop-b", Gateway: "100.64.0.2", Interface: "easytier0", Table: 4200},
		{POPID: "pop-b", Gateway: "100.64.0.3", Interface: "easytier1", Table: 4201},
	}
	_, err := CompileServiceChainPlan(serviceChainProfile(controlcontract.RouteSelector{DestinationCIDR: "203.0.113.0/24"}, "pop-b"), targets, serviceChainOptions())
	assertServiceChainError(t, err, "duplicate service-chain transport target POP id")
}

func TestCompileServiceChainPlanRejectsDuplicateTargetTables(t *testing.T) {
	targets := []ServiceChainTransportTarget{
		{POPID: "pop-b", Gateway: "100.64.0.2", Interface: "easytier0", Table: 4200},
		{POPID: "pop-c", Gateway: "100.64.0.3", Interface: "easytier1", Table: 4200},
	}
	_, err := CompileServiceChainPlan(serviceChainProfile(controlcontract.RouteSelector{DestinationCIDR: "203.0.113.0/24"}, "pop-b"), targets, serviceChainOptions())
	assertServiceChainError(t, err, "duplicate service-chain transport target table")
}

func TestServiceChainPlanRendersIPv6SelectorsAndCommands(t *testing.T) {
	profile := serviceChainProfile(controlcontract.RouteSelector{
		SourceCIDR:      "2001:db8:1::/64",
		DestinationCIDR: "2001:db8:2::/64",
		Protocol:        controlcontract.ProtocolUDP,
		Ports:           &controlcontract.PortRange{Start: 53, End: 53},
	}, "pop-b")
	plan, err := CompileServiceChainPlan(profile,
		[]ServiceChainTransportTarget{{POPID: "pop-b", Gateway: "fe80::2", Interface: "easytier0", Table: 4200}},
		serviceChainOptions(),
	)
	if err != nil {
		t.Fatalf("compile IPv6 plan: %v", err)
	}

	nft, err := plan.RenderNftables()
	if err != nil {
		t.Fatalf("render IPv6 nftables: %v", err)
	}
	for _, want := range []string{
		"ip6 saddr 2001:db8:1::/64",
		"ip6 daddr 2001:db8:2::/64",
		"udp dport 53-53",
	} {
		if !strings.Contains(nft, want) {
			t.Fatalf("missing %q in:\n%s", want, nft)
		}
	}

	commands, err := plan.RenderIPRouteCommands()
	if err != nil {
		t.Fatalf("render IPv6 routes: %v", err)
	}
	want := []string{
		"ip -6 route replace ::/0 via fe80::2 dev easytier0 table 4200",
		"ip -6 rule add fwmark 4000 table 4200 priority 14000",
	}
	if !reflect.DeepEqual(want, commands) {
		t.Fatalf("IPv6 commands got %v, want %v", commands, want)
	}
}

func TestServiceChainPlanRendersAfterExistingConfigPolicyMarking(t *testing.T) {
	plan, err := CompileServiceChainPlan(
		serviceChainProfile(controlcontract.RouteSelector{DestinationCIDR: "203.0.113.0/24"}, "pop-b"),
		serviceChainTargets(),
		serviceChainOptions(),
	)
	if err != nil {
		t.Fatalf("compile service-chain plan: %v", err)
	}
	serviceChainNft, err := plan.RenderNftables()
	if err != nil {
		t.Fatalf("render service-chain nftables: %v", err)
	}

	config := testConfig()
	config.RouteRules = []RouteRule{{
		Name:       "existing-policy",
		Mark:       100,
		MatchCIDR:  "198.51.100.0/24",
		Table:      100,
		DestCIDR:   "0.0.0.0/0",
		Interface:  "wg-existing",
		Preference: 1000,
	}}
	configNft, err := config.RenderNftables()
	if err != nil {
		t.Fatalf("render config nftables: %v", err)
	}

	if want := "type filter hook prerouting priority -140; policy accept;"; !strings.Contains(serviceChainNft, want) {
		t.Fatalf("service-chain nftables missing %q:\n%s", want, serviceChainNft)
	}
	if want := "type filter hook prerouting priority mangle; policy accept;"; !strings.Contains(configNft, want) {
		t.Fatalf("config nftables missing %q:\n%s", want, configNft)
	}
}

func TestCompileServiceChainPlanRejectsExistingRouteRuleMark(t *testing.T) {
	options := serviceChainOptions()
	options.ExistingRouteRules = []RouteRule{serviceChainExistingRouteRule("existing-mark", 4000, 4201, 15000)}

	_, err := CompileServiceChainPlan(
		serviceChainProfile(controlcontract.RouteSelector{DestinationCIDR: "203.0.113.0/24"}, "pop-b"),
		serviceChainTargets(),
		options,
	)
	assertServiceChainError(t, err, `route "enterprise" mark 4000 conflicts with existing route rule "existing-mark"`)
}

func TestCompileServiceChainPlanRejectsExistingRouteRulePreference(t *testing.T) {
	options := serviceChainOptions()
	options.ExistingRouteRules = []RouteRule{serviceChainExistingRouteRule("existing-preference", 4999, 4201, 14000)}

	_, err := CompileServiceChainPlan(
		serviceChainProfile(controlcontract.RouteSelector{DestinationCIDR: "203.0.113.0/24"}, "pop-b"),
		serviceChainTargets(),
		options,
	)
	assertServiceChainError(t, err, `route "enterprise" preference 14000 conflicts with existing route rule "existing-preference"`)
}

func TestCompileServiceChainPlanRejectsExistingRouteRuleTable(t *testing.T) {
	options := serviceChainOptions()
	options.ExistingRouteRules = []RouteRule{serviceChainExistingRouteRule("existing-table", 4999, 4200, 15000)}

	_, err := CompileServiceChainPlan(
		serviceChainProfile(controlcontract.RouteSelector{DestinationCIDR: "203.0.113.0/24"}, "pop-b"),
		serviceChainTargets(),
		options,
	)
	assertServiceChainError(t, err, `route "enterprise" table 4200 conflicts with existing route rule "existing-table"`)
}

func TestCompileServiceChainPlanAllowsDistinctExistingRouteRuleValues(t *testing.T) {
	options := serviceChainOptions()
	options.ExistingRouteRules = []RouteRule{serviceChainExistingRouteRule("existing-distinct", 4999, 4201, 15000)}

	if _, err := CompileServiceChainPlan(
		serviceChainProfile(controlcontract.RouteSelector{DestinationCIDR: "203.0.113.0/24"}, "pop-b"),
		serviceChainTargets(),
		options,
	); err != nil {
		t.Fatalf("compile with distinct existing route rule values: %v", err)
	}
}

func TestCompileServiceChainPlanDoesNotMutateExistingRouteRuleReservations(t *testing.T) {
	existing := []RouteRule{serviceChainExistingRouteRule("existing-distinct", 4999, 4201, 15000)}
	wantExisting := append([]RouteRule(nil), existing...)
	options := serviceChainOptions()
	options.ExistingRouteRules = existing

	if _, err := CompileServiceChainPlan(
		serviceChainProfile(controlcontract.RouteSelector{DestinationCIDR: "203.0.113.0/24"}, "pop-b"),
		serviceChainTargets(),
		options,
	); err != nil {
		t.Fatalf("compile with existing route rule reservations: %v", err)
	}
	if !reflect.DeepEqual(existing, wantExisting) {
		t.Fatalf("existing route rules mutated: got %+v, want %+v", existing, wantExisting)
	}
}

func serviceChainProfile(selector controlcontract.RouteSelector, firstHop string) controlcontract.PopProfile {
	return controlcontract.PopProfile{
		ID:          "pop-a-profile",
		PrincipalID: "pop-a",
		Routes: []controlcontract.RoutePolicy{{
			ID:       "enterprise",
			Selector: selector,
			Chain: controlcontract.ServiceChain{
				ID:   "a-b",
				Hops: []string{firstHop},
			},
		}},
	}
}

func serviceChainTargets() []ServiceChainTransportTarget {
	return []ServiceChainTransportTarget{{
		POPID: "pop-b", Gateway: "100.64.0.2", Interface: "easytier0", Table: 4200,
	}}
}

func serviceChainOptions() ServiceChainCompileOptions {
	return ServiceChainCompileOptions{
		LocalPOPID:       "pop-a",
		IngressInterface: "xfrm0",
		MarkBase:         4000,
		PreferenceBase:   14000,
	}
}

func serviceChainExistingRouteRule(name string, mark, table, preference int) RouteRule {
	return RouteRule{
		Name:       name,
		Mark:       mark,
		Table:      table,
		DestCIDR:   "0.0.0.0/0",
		Interface:  "wg-existing",
		Preference: preference,
	}
}

func assertServiceChainError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want substring %q", err, want)
	}
}
