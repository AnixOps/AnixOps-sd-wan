package linuxgw

import (
	"context"
	"errors"
	"strings"
	"testing"

	"anixops-sd-wan/internal/policy"
)

func TestParseConntrackObservations(t *testing.T) {
	input := strings.NewReader(strings.Join([]string{
		`tcp      6 431999 ESTABLISHED src=192.168.10.55 dst=203.0.113.10 sport=53100 dport=443 src=203.0.113.10 dst=192.168.10.55 sport=443 dport=53100 [ASSURED] mark=0 use=1`,
		`udp      17 29 src=192.168.10.56 dst=2001:db8::20 sport=53000 dport=443 src=2001:db8::20 dst=192.168.10.56 sport=443 dport=53000 mark=0 use=1`,
		`tcp      6 60 SYN_SENT src=10.99.0.10 dst=198.51.100.10 sport=53001 dport=443 [UNREPLIED]`,
		`tcp      6 60 SYN_SENT src=192.168.10.57 sport=53002 dport=443`,
	}, "\n"))

	observations, err := ParseConntrackObservations("tenant-a", input, PacketObservationOptions{
		SourceCIDRs: []string{"192.168.10.0/24"},
	})
	if err != nil {
		t.Fatalf("parse conntrack observations: %v", err)
	}
	if len(observations) != 2 {
		t.Fatalf("expected two packet observations, got %+v", observations)
	}
	if observations[0].TenantID != "tenant-a" || observations[0].IP != "203.0.113.10" {
		t.Fatalf("unexpected first observation: %+v", observations[0])
	}
	if observations[1].IP != "2001:db8::20" {
		t.Fatalf("unexpected second observation: %+v", observations[1])
	}
}

func TestConntrackObservationsFeedObservedPolicyRoutePlan(t *testing.T) {
	observations, err := ParseConntrackObservations("tenant-a", strings.NewReader(
		`tcp 6 120 SYN_SENT src=192.168.10.55 dst=203.0.113.44 sport=53001 dport=443 [UNREPLIED]`,
	), PacketObservationOptions{SourceCIDRs: []string{"192.168.10.0/24"}})
	if err != nil {
		t.Fatalf("parse conntrack observations: %v", err)
	}
	rules, err := PlanObservedPolicyRouteRules(observations, nil, []policy.Rule{{
		ID:           "packet-egress",
		TenantID:     "tenant-a",
		Priority:     100,
		IPCIDR:       "203.0.113.0/24",
		EgressNodeID: "egress-a",
	}}, []EgressRouteTarget{{
		NodeID:    "egress-a",
		Interface: "wg-egress",
		Table:     220,
	}}, PolicyRoutePlanOptions{MarkBase: 800, PreferenceBase: 18000})
	if err != nil {
		t.Fatalf("plan observed packet route rules: %v", err)
	}
	if len(rules) != 1 || rules[0].MatchCIDR != "203.0.113.44/32" || rules[0].Mark != 800 {
		t.Fatalf("unexpected route rules from packet observation: %+v", rules)
	}
}

func TestParseConntrackLineRejectsInvalidInputs(t *testing.T) {
	if _, _, err := ParseConntrackLine("", `tcp 6 120 src=192.168.10.55 dst=203.0.113.44`, PacketObservationOptions{}); err == nil {
		t.Fatal("expected missing tenant to be rejected")
	}
	if _, _, err := ParseConntrackLine("tenant-a", `tcp 6 120 src=192.168.10.55 dst=203.0.113.44`, PacketObservationOptions{
		SourceCIDRs: []string{"not-cidr"},
	}); err == nil {
		t.Fatal("expected invalid source cidr to be rejected")
	}
}

func TestStreamConntrackObservations(t *testing.T) {
	input := strings.NewReader(strings.Join([]string{
		`tcp 6 120 src=192.168.10.55 dst=203.0.113.44 sport=53001 dport=443`,
		`tcp 6 120 src=10.99.0.10 dst=203.0.113.45 sport=53002 dport=443`,
		`udp 17 30 src=192.168.10.56 dst=203.0.113.46 sport=53003 dport=443`,
	}, "\n"))
	var observed []policy.Request

	err := StreamConntrackObservations(context.Background(), "tenant-a", input, PacketObservationOptions{
		SourceCIDRs: []string{"192.168.10.0/24"},
	}, func(ctx context.Context, request policy.Request) error {
		observed = append(observed, request)
		return nil
	})
	if err != nil {
		t.Fatalf("stream conntrack observations: %v", err)
	}
	if len(observed) != 2 || observed[0].IP != "203.0.113.44" || observed[1].IP != "203.0.113.46" {
		t.Fatalf("unexpected streamed packet observations: %+v", observed)
	}
}

func TestStreamConntrackObservationsReturnsHandlerError(t *testing.T) {
	handlerErr := errors.New("handler failed")
	err := StreamConntrackObservations(context.Background(), "tenant-a", strings.NewReader(
		`tcp 6 120 src=192.168.10.55 dst=203.0.113.44 sport=53001 dport=443`,
	), PacketObservationOptions{}, func(ctx context.Context, request policy.Request) error {
		return handlerErr
	})
	if !errors.Is(err, handlerErr) {
		t.Fatalf("expected handler error, got %v", err)
	}
}

func TestStreamConntrackObservationsHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := StreamConntrackObservations(ctx, "tenant-a", strings.NewReader(
		`tcp 6 120 src=192.168.10.55 dst=203.0.113.44 sport=53001 dport=443`,
	), PacketObservationOptions{}, func(ctx context.Context, request policy.Request) error {
		t.Fatal("handler should not be called after cancellation")
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
