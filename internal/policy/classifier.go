package policy

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

type ClassificationRule struct {
	ID           string       `json:"id"`
	Priority     int          `json:"priority"`
	DomainSuffix string       `json:"domain_suffix,omitempty"`
	IPCIDR       string       `json:"ip_cidr,omitempty"`
	ASN          int          `json:"asn,omitempty"`
	Class        TrafficClass `json:"class"`
}

func (r ClassificationRule) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("classification rule id is required")
	}
	if r.Class == "" {
		return fmt.Errorf("classification rule class is required")
	}
	if r.DomainSuffix == "" && r.IPCIDR == "" && r.ASN == 0 {
		return fmt.Errorf("classification rule %q must define at least one match condition", r.ID)
	}
	if r.IPCIDR != "" {
		if _, _, err := net.ParseCIDR(r.IPCIDR); err != nil {
			return fmt.Errorf("classification rule %q has invalid CIDR: %w", r.ID, err)
		}
	}
	return nil
}

type Classifier struct {
	rules []ClassificationRule
}

func NewClassifier(rules []ClassificationRule) (*Classifier, error) {
	copied := append([]ClassificationRule(nil), rules...)
	for _, rule := range copied {
		if err := rule.Validate(); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(copied, func(i, j int) bool {
		if copied[i].Priority == copied[j].Priority {
			return copied[i].ID < copied[j].ID
		}
		return copied[i].Priority > copied[j].Priority
	})
	return &Classifier{rules: copied}, nil
}

func (c *Classifier) Classify(request Request) TrafficClass {
	if request.Class != "" {
		return request.Class
	}
	for _, rule := range c.rules {
		if classificationRuleMatches(rule, request) {
			return rule.Class
		}
	}
	return ClassDefault
}

func classificationRuleMatches(rule ClassificationRule, request Request) bool {
	matched := false
	if rule.DomainSuffix != "" {
		if !domainMatches(request.Domain, rule.DomainSuffix) {
			return false
		}
		matched = true
	}
	if rule.IPCIDR != "" {
		if !ipMatches(request.IP, rule.IPCIDR) {
			return false
		}
		matched = true
	}
	if rule.ASN != 0 {
		if request.ASN != rule.ASN {
			return false
		}
		matched = true
	}
	return matched
}
