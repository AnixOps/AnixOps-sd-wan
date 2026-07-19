package controlcontract

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	SchemaVersionV1               = "anixops.sdwan.delivery/v1"
	RequiredMetadataRetentionDays = 7
)

type BundleKind string

const (
	BundleKindClient BundleKind = "client"
	BundleKindPop    BundleKind = "pop"
)

type Transport string

const (
	TransportIKEv2 Transport = "ikev2"
)

type Protocol string

const (
	ProtocolTCP Protocol = "tcp"
	ProtocolUDP Protocol = "udp"
)

type Profile struct {
	SchemaVersion string         `json:"schema_version"`
	Kind          BundleKind     `json:"kind"`
	Client        *ClientProfile `json:"client,omitempty"`
	Pop           *PopProfile    `json:"pop,omitempty"`
}

func (p Profile) Validate() error {
	if p.SchemaVersion != SchemaVersionV1 {
		return fmt.Errorf("unsupported profile schema %q", p.SchemaVersion)
	}

	switch p.Kind {
	case BundleKindClient:
		if p.Client == nil || p.Pop != nil {
			return fmt.Errorf("client profile must contain only client payload")
		}
		return p.Client.Validate()
	case BundleKindPop:
		if p.Pop == nil || p.Client != nil {
			return fmt.Errorf("pop profile must contain only pop payload")
		}
		return p.Pop.Validate()
	default:
		return fmt.Errorf("unsupported profile kind %q", p.Kind)
	}
}

type ClientProfile struct {
	ID          string         `json:"id"`
	PrincipalID string         `json:"principal_id"`
	Transport   Transport      `json:"transport"`
	POPs        []PopReference `json:"pops"`
	MITM        *MITMProfile   `json:"mitm,omitempty"`
}

func (p ClientProfile) Validate() error {
	if err := validateIdentifier("client profile id", p.ID); err != nil {
		return err
	}
	if err := validateIdentifier("client principal id", p.PrincipalID); err != nil {
		return err
	}
	if p.Transport != TransportIKEv2 {
		return fmt.Errorf("unsupported client transport %q", p.Transport)
	}
	if len(p.POPs) == 0 {
		return fmt.Errorf("client profile must define at least one POP")
	}

	popIDs := make(map[string]struct{}, len(p.POPs))
	for index, pop := range p.POPs {
		if err := pop.Validate(); err != nil {
			return fmt.Errorf("client POP %d: %w", index, err)
		}
		id := strings.TrimSpace(pop.ID)
		if _, exists := popIDs[id]; exists {
			return fmt.Errorf("duplicate client POP id %q", id)
		}
		popIDs[id] = struct{}{}
	}
	if p.MITM != nil {
		if err := p.MITM.Validate(); err != nil {
			return fmt.Errorf("client MITM policy: %w", err)
		}
	}
	return nil
}

type PopReference struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
}

func (p PopReference) Validate() error {
	if err := validateIdentifier("POP id", p.ID); err != nil {
		return err
	}
	endpoint := strings.TrimSpace(p.Endpoint)
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || strings.TrimSpace(host) == "" {
		return fmt.Errorf("invalid endpoint %q", p.Endpoint)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return fmt.Errorf("invalid endpoint %q", p.Endpoint)
	}
	return nil
}

type MITMProfile struct {
	AllowedDomainSuffixes []string `json:"allowed_domain_suffixes"`
	RequireConsent        bool     `json:"require_consent"`
	BlockQUIC             bool     `json:"block_quic"`
	BlockPinnedTLS        bool     `json:"block_pinned_tls"`
	MetadataRetentionDays int      `json:"metadata_retention_days"`
}

func (p MITMProfile) Validate() error {
	if len(p.AllowedDomainSuffixes) == 0 {
		return fmt.Errorf("MITM policy must define at least one allowlisted domain")
	}
	seen := make(map[string]struct{}, len(p.AllowedDomainSuffixes))
	for _, suffix := range p.AllowedDomainSuffixes {
		normalized, err := normalizeDomainSuffix(suffix)
		if err != nil {
			return fmt.Errorf("invalid MITM allowlisted domain %q: %w", suffix, err)
		}
		if _, exists := seen[normalized]; exists {
			return fmt.Errorf("duplicate MITM allowlisted domain %q", normalized)
		}
		seen[normalized] = struct{}{}
	}
	if !p.RequireConsent {
		return fmt.Errorf("MITM policy must require consent")
	}
	if !p.BlockQUIC {
		return fmt.Errorf("MITM policy must block QUIC for selected traffic")
	}
	if !p.BlockPinnedTLS {
		return fmt.Errorf("MITM policy must block pinned TLS for selected traffic")
	}
	if p.MetadataRetentionDays != RequiredMetadataRetentionDays {
		return fmt.Errorf("MITM metadata retention must be %d days", RequiredMetadataRetentionDays)
	}
	return nil
}

type PopProfile struct {
	ID          string        `json:"id"`
	PrincipalID string        `json:"principal_id"`
	Routes      []RoutePolicy `json:"routes"`
}

func (p PopProfile) Validate() error {
	if err := validateIdentifier("POP profile id", p.ID); err != nil {
		return err
	}
	if err := validateIdentifier("POP principal id", p.PrincipalID); err != nil {
		return err
	}
	if len(p.Routes) == 0 {
		return fmt.Errorf("POP profile must define at least one route")
	}

	routeIDs := make(map[string]struct{}, len(p.Routes))
	for index, route := range p.Routes {
		if err := route.Validate(); err != nil {
			return fmt.Errorf("POP route %d: %w", index, err)
		}
		id := strings.TrimSpace(route.ID)
		if _, exists := routeIDs[id]; exists {
			return fmt.Errorf("duplicate POP route id %q", id)
		}
		routeIDs[id] = struct{}{}
	}
	return nil
}

type RoutePolicy struct {
	ID             string        `json:"id"`
	Selector       RouteSelector `json:"selector"`
	Chain          ServiceChain  `json:"chain"`
	DirectFallback bool          `json:"direct_fallback,omitempty"`
}

func (p RoutePolicy) Validate() error {
	if err := validateIdentifier("route id", p.ID); err != nil {
		return err
	}
	if p.DirectFallback {
		return fmt.Errorf("direct fallback is forbidden for a service-chain route")
	}
	if err := p.Selector.Validate(); err != nil {
		return fmt.Errorf("route selector: %w", err)
	}
	if err := p.Chain.Validate(); err != nil {
		return fmt.Errorf("service chain: %w", err)
	}
	return nil
}

type RouteSelector struct {
	SourceCIDR      string     `json:"source_cidr,omitempty"`
	DestinationCIDR string     `json:"destination_cidr,omitempty"`
	DomainSuffix    string     `json:"domain_suffix,omitempty"`
	TrafficClass    string     `json:"traffic_class,omitempty"`
	Protocol        Protocol   `json:"protocol,omitempty"`
	Ports           *PortRange `json:"ports,omitempty"`
}

func (s RouteSelector) Validate() error {
	if strings.TrimSpace(s.SourceCIDR) != "" {
		if _, _, err := net.ParseCIDR(s.SourceCIDR); err != nil {
			return fmt.Errorf("invalid source CIDR %q", s.SourceCIDR)
		}
	}
	if strings.TrimSpace(s.DestinationCIDR) != "" {
		if _, _, err := net.ParseCIDR(s.DestinationCIDR); err != nil {
			return fmt.Errorf("invalid destination CIDR %q", s.DestinationCIDR)
		}
	}
	if strings.TrimSpace(s.DomainSuffix) != "" {
		if _, err := normalizeDomainSuffix(s.DomainSuffix); err != nil {
			return fmt.Errorf("invalid domain suffix %q: %w", s.DomainSuffix, err)
		}
	}
	if strings.TrimSpace(s.TrafficClass) != "" {
		if err := validateIdentifier("traffic class", s.TrafficClass); err != nil {
			return err
		}
	}
	if s.Protocol != "" && s.Protocol != ProtocolTCP && s.Protocol != ProtocolUDP {
		return fmt.Errorf("unsupported L4 protocol %q", s.Protocol)
	}
	if s.Ports != nil {
		if s.Protocol != ProtocolTCP && s.Protocol != ProtocolUDP {
			return fmt.Errorf("ports require TCP or UDP protocol")
		}
		if err := s.Ports.Validate(); err != nil {
			return err
		}
	}
	if strings.TrimSpace(s.SourceCIDR) == "" &&
		strings.TrimSpace(s.DestinationCIDR) == "" &&
		strings.TrimSpace(s.DomainSuffix) == "" &&
		strings.TrimSpace(s.TrafficClass) == "" &&
		s.Protocol == "" &&
		s.Ports == nil {
		return fmt.Errorf("route selector must define at least one match")
	}
	return nil
}

type PortRange struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}

func (p PortRange) Validate() error {
	if p.Start == 0 || p.End == 0 || p.Start > p.End {
		return fmt.Errorf("invalid port range %d-%d", p.Start, p.End)
	}
	return nil
}

type ServiceChain struct {
	ID         string   `json:"id"`
	Hops       []string `json:"hops"`
	ReturnHops []string `json:"return_hops,omitempty"`
}

func (c ServiceChain) Validate() error {
	if err := validateIdentifier("service chain id", c.ID); err != nil {
		return err
	}
	if len(c.Hops) == 0 {
		return fmt.Errorf("service chain must define at least one hop")
	}
	if err := validateHopList("service chain hop", c.Hops); err != nil {
		return err
	}
	if len(c.ReturnHops) > 0 {
		if err := validateHopList("service chain return hop", c.ReturnHops); err != nil {
			return err
		}
	}
	return nil
}

func validateHopList(field string, hops []string) error {
	seen := make(map[string]struct{}, len(hops))
	for _, hop := range hops {
		if err := validateIdentifier(field, hop); err != nil {
			return err
		}
		normalized := strings.TrimSpace(hop)
		if _, exists := seen[normalized]; exists {
			return fmt.Errorf("duplicate %s %q", field, normalized)
		}
		seen[normalized] = struct{}{}
	}
	return nil
}

func validateIdentifier(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", field)
	}
	return nil
}

func normalizeDomainSuffix(value string) (string, error) {
	normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if normalized == "" {
		return "", fmt.Errorf("domain is required")
	}
	if strings.HasPrefix(normalized, ".") || strings.ContainsAny(normalized, "/:@*") {
		return "", fmt.Errorf("domain contains unsupported characters")
	}
	for _, label := range strings.Split(normalized, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("invalid domain label")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') &&
				character != '-' {
				return "", fmt.Errorf("invalid domain label")
			}
		}
	}
	return normalized, nil
}
