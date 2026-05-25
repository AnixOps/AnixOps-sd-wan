package policy

import "testing"

func TestClassifierMapsObservedTrafficToClass(t *testing.T) {
	classifier, err := NewClassifier([]ClassificationRule{
		{
			ID:           "ai-domain",
			Priority:     100,
			DomainSuffix: "openai.com",
			Class:        ClassAI,
		},
		{
			ID:       "video-asn",
			Priority: 90,
			ASN:      64512,
			Class:    ClassVideo,
		},
		{
			ID:       "enterprise-ip",
			Priority: 80,
			IPCIDR:   "10.10.0.0/16",
			Class:    ClassEnterprise,
		},
	})
	if err != nil {
		t.Fatalf("new classifier: %v", err)
	}

	cases := []struct {
		name string
		req  Request
		want TrafficClass
	}{
		{name: "domain", req: Request{Domain: "api.openai.com"}, want: ClassAI},
		{name: "asn", req: Request{ASN: 64512}, want: ClassVideo},
		{name: "ip", req: Request{IP: "10.10.1.10"}, want: ClassEnterprise},
		{name: "default", req: Request{Domain: "example.org"}, want: ClassDefault},
	}
	for _, tc := range cases {
		if got := classifier.Classify(tc.req); got != tc.want {
			t.Fatalf("%s expected %s, got %s", tc.name, tc.want, got)
		}
	}
}

func TestClassifierKeepsExplicitClass(t *testing.T) {
	classifier, err := NewClassifier([]ClassificationRule{{
		ID:           "ai-domain",
		Priority:     100,
		DomainSuffix: "openai.com",
		Class:        ClassAI,
	}})
	if err != nil {
		t.Fatalf("new classifier: %v", err)
	}

	if got := classifier.Classify(Request{Domain: "api.openai.com", Class: ClassEnterprise}); got != ClassEnterprise {
		t.Fatalf("expected explicit class to win, got %s", got)
	}
}
