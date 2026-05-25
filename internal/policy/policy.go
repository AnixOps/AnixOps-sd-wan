package policy

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

type TrafficClass string

const (
	ClassAI         TrafficClass = "ai"
	ClassVideo      TrafficClass = "video"
	ClassEnterprise TrafficClass = "enterprise"
	ClassDomestic   TrafficClass = "domestic"
	ClassDefault    TrafficClass = "default"
)

type Rule struct {
	ID           string       `json:"id"`
	TenantID     string       `json:"tenant_id"`
	Priority     int          `json:"priority"`
	DomainSuffix string       `json:"domain_suffix,omitempty"`
	IPCIDR       string       `json:"ip_cidr,omitempty"`
	ASN          int          `json:"asn,omitempty"`
	Class        TrafficClass `json:"class,omitempty"`
	EgressNodeID string       `json:"egress_node_id"`
}

func (r Rule) Validate() error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("rule id is required")
	}
	if strings.TrimSpace(r.TenantID) == "" {
		return fmt.Errorf("rule tenant id is required")
	}
	if strings.TrimSpace(r.EgressNodeID) == "" {
		return fmt.Errorf("rule egress node id is required")
	}
	if r.DomainSuffix == "" && r.IPCIDR == "" && r.ASN == 0 && r.Class == "" {
		return fmt.Errorf("rule %q must define at least one match condition", r.ID)
	}
	if r.IPCIDR != "" {
		if _, _, err := net.ParseCIDR(r.IPCIDR); err != nil {
			return fmt.Errorf("rule %q has invalid CIDR: %w", r.ID, err)
		}
	}
	return nil
}

type Request struct {
	TenantID string       `json:"tenant_id"`
	Domain   string       `json:"domain,omitempty"`
	IP       string       `json:"ip,omitempty"`
	ASN      int          `json:"asn,omitempty"`
	Class    TrafficClass `json:"class,omitempty"`
}

type Decision struct {
	Matched      bool         `json:"matched"`
	RuleID       string       `json:"rule_id,omitempty"`
	EgressNodeID string       `json:"egress_node_id,omitempty"`
	Class        TrafficClass `json:"class,omitempty"`
}

type Engine struct {
	rules []Rule
}

func NewEngine(rules []Rule) (*Engine, error) {
	copied := append([]Rule(nil), rules...)
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
	return &Engine{rules: copied}, nil
}

func (e *Engine) Evaluate(request Request) Decision {
	for _, rule := range e.rules {
		if rule.TenantID != request.TenantID {
			continue
		}
		if ruleMatches(rule, request) {
			class := request.Class
			if class == "" {
				class = rule.Class
			}
			return Decision{
				Matched:      true,
				RuleID:       rule.ID,
				EgressNodeID: rule.EgressNodeID,
				Class:        class,
			}
		}
	}
	return Decision{}
}

func ruleMatches(rule Rule, request Request) bool {
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
	if rule.Class != "" {
		if request.Class != rule.Class {
			return false
		}
		matched = true
	}
	return matched
}

func domainMatches(domain, suffix string) bool {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	s := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(suffix)), ".")
	if d == "" || s == "" {
		return false
	}
	return d == s || strings.HasSuffix(d, "."+s)
}

func ipMatches(ipValue, cidr string) bool {
	ip := net.ParseIP(ipValue)
	if ip == nil {
		return false
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}
