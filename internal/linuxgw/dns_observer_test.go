package linuxgw

import (
	"context"
	"errors"
	"strings"
	"testing"

	"anixops-sd-wan/internal/policy"
)

func TestParseDNSMasqLogObservations(t *testing.T) {
	input := strings.NewReader(strings.Join([]string{
		`May 13 10:00:00 dnsmasq[100]: query[A] api.openai.com from 192.168.10.55`,
		`May 13 10:00:00 dnsmasq[100]: reply api.openai.com is 203.0.113.10`,
		`May 13 10:00:01 dnsmasq[100]: cached video.example. is 2001:db8::10`,
		`May 13 10:00:02 dnsmasq[100]: reply cname.example is edge.example`,
	}, "\n"))

	observations, err := ParseDNSMasqLogObservations("tenant-a", input)
	if err != nil {
		t.Fatalf("parse dnsmasq observations: %v", err)
	}
	if len(observations) != 2 {
		t.Fatalf("expected two DNS observations, got %+v", observations)
	}
	if observations[0].TenantID != "tenant-a" || observations[0].Domain != "api.openai.com" || observations[0].IP != "203.0.113.10" {
		t.Fatalf("unexpected first observation: %+v", observations[0])
	}
	if observations[1].Domain != "video.example" || observations[1].IP != "2001:db8::10" {
		t.Fatalf("unexpected second observation: %+v", observations[1])
	}
}

func TestDNSMasqObservationsFeedObservedPolicyRoutePlan(t *testing.T) {
	observations, err := ParseDNSMasqLogObservations("tenant-a", strings.NewReader(
		`dnsmasq[100]: reply api.openai.com is 203.0.113.10`,
	))
	if err != nil {
		t.Fatalf("parse dnsmasq observations: %v", err)
	}
	classifier, err := policy.NewClassifier([]policy.ClassificationRule{{
		ID:           "ai-domain",
		Priority:     100,
		DomainSuffix: "openai.com",
		Class:        policy.ClassAI,
	}})
	if err != nil {
		t.Fatalf("new classifier: %v", err)
	}
	rules, err := PlanObservedPolicyRouteRules(observations, classifier, []policy.Rule{{
		ID:           "ai-egress",
		TenantID:     "tenant-a",
		Priority:     100,
		Class:        policy.ClassAI,
		EgressNodeID: "egress-ai",
	}}, []EgressRouteTarget{{
		NodeID:    "egress-ai",
		Interface: "wg-ai",
		Table:     202,
	}}, PolicyRoutePlanOptions{MarkBase: 500, PreferenceBase: 15000})
	if err != nil {
		t.Fatalf("plan observed policy route rules: %v", err)
	}
	if len(rules) != 1 || rules[0].MatchCIDR != "203.0.113.10/32" || rules[0].Mark != 500 {
		t.Fatalf("unexpected route rules from dns observation: %+v", rules)
	}
}

func TestParseDNSMasqLogLineRejectsMissingTenant(t *testing.T) {
	_, _, err := ParseDNSMasqLogLine("", `dnsmasq[100]: reply api.openai.com is 203.0.113.10`)
	if err == nil {
		t.Fatal("expected missing tenant to be rejected")
	}
}

func TestStreamDNSMasqLogObservations(t *testing.T) {
	input := strings.NewReader(strings.Join([]string{
		`dnsmasq[100]: query[A] api.openai.com from 192.168.10.55`,
		`dnsmasq[100]: reply api.openai.com is 203.0.113.10`,
		`dnsmasq[100]: reply cname.example is edge.example`,
		`dnsmasq[100]: cached video.example is 2001:db8::10`,
	}, "\n"))

	var observed []policy.Request
	err := StreamDNSMasqLogObservations(context.Background(), "tenant-a", input, func(ctx context.Context, request policy.Request) error {
		observed = append(observed, request)
		return nil
	})
	if err != nil {
		t.Fatalf("stream dnsmasq observations: %v", err)
	}
	if len(observed) != 2 {
		t.Fatalf("expected two streamed observations, got %+v", observed)
	}
	if observed[0].Domain != "api.openai.com" || observed[1].Domain != "video.example" {
		t.Fatalf("unexpected streamed observations: %+v", observed)
	}
}

func TestStreamDNSMasqLogObservationsReturnsHandlerError(t *testing.T) {
	handlerErr := errors.New("handler failed")
	err := StreamDNSMasqLogObservations(context.Background(), "tenant-a", strings.NewReader(
		`dnsmasq[100]: reply api.openai.com is 203.0.113.10`,
	), func(ctx context.Context, request policy.Request) error {
		return handlerErr
	})
	if err == nil {
		t.Fatal("expected handler error")
	}
	if !strings.Contains(err.Error(), handlerErr.Error()) {
		t.Fatalf("expected handler error, got %v", err)
	}
}

func TestStreamDNSMasqLogObservationsHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := StreamDNSMasqLogObservations(ctx, "tenant-a", strings.NewReader(
		`dnsmasq[100]: reply api.openai.com is 203.0.113.10`,
	), func(ctx context.Context, request policy.Request) error {
		t.Fatal("handler should not be called after context cancellation")
		return nil
	})
	if err == nil {
		t.Fatal("expected context cancellation")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
