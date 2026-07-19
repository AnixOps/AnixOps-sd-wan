package linuxgw

import (
	"fmt"
	"net"
	"strings"

	"anixops-sd-wan/internal/controlcontract"
)

const (
	DefaultServiceChainMarkBase       = 4000
	DefaultServiceChainPreferenceBase = 14000
	DefaultServiceChainNftPriority    = -140
)

type ServiceChainIPFamily string

const (
	ServiceChainIPv4 ServiceChainIPFamily = "ipv4"
	ServiceChainIPv6 ServiceChainIPFamily = "ipv6"
)

type ServiceChainTransportTarget struct {
	POPID     string
	Gateway   string
	Interface string
	Table     int
}

type ServiceChainCompileOptions struct {
	LocalPOPID         string
	IngressInterface   string
	MarkBase           int
	PreferenceBase     int
	ExistingRouteRules []RouteRule
}

type ServiceChainRoute struct {
	RouteID    string
	ChainID    string
	NextPOPID  string
	ReturnHops []string
	Selector   controlcontract.RouteSelector
	Family     ServiceChainIPFamily
	Mark       int
	Preference int
	Target     ServiceChainTransportTarget
}

type ServiceChainPlan struct {
	LocalPOPID       string
	IngressInterface string
	Routes           []ServiceChainRoute
}

// CompileServiceChainPlan creates desired nftables and policy-route state without applying it.
func CompileServiceChainPlan(profile controlcontract.PopProfile, targets []ServiceChainTransportTarget, options ServiceChainCompileOptions) (ServiceChainPlan, error) {
	if err := profile.Validate(); err != nil {
		return ServiceChainPlan{}, fmt.Errorf("validate POP profile: %w", err)
	}

	normalizedOptions, err := normalizeServiceChainCompileOptions(options)
	if err != nil {
		return ServiceChainPlan{}, err
	}
	principalID := strings.TrimSpace(profile.PrincipalID)
	if normalizedOptions.LocalPOPID != principalID {
		return ServiceChainPlan{}, fmt.Errorf("local POP id %q does not match profile principal id %q", normalizedOptions.LocalPOPID, principalID)
	}

	targetsByPOPID, err := serviceChainTargetsByPOPID(targets)
	if err != nil {
		return ServiceChainPlan{}, err
	}

	routes := make([]ServiceChainRoute, 0, len(profile.Routes))
	for index, policy := range profile.Routes {
		mark, err := serviceChainSequenceValue(normalizedOptions.MarkBase, index, "mark")
		if err != nil {
			return ServiceChainPlan{}, err
		}
		preference, err := serviceChainSequenceValue(normalizedOptions.PreferenceBase, index, "preference")
		if err != nil {
			return ServiceChainPlan{}, err
		}

		nextPOPID := strings.TrimSpace(policy.Chain.Hops[0])
		if nextPOPID == normalizedOptions.LocalPOPID {
			return ServiceChainPlan{}, fmt.Errorf("route %q first hop %q is the local POP", strings.TrimSpace(policy.ID), nextPOPID)
		}
		target, exists := targetsByPOPID[nextPOPID]
		if !exists {
			return ServiceChainPlan{}, fmt.Errorf("route %q references unknown first hop target %q", strings.TrimSpace(policy.ID), nextPOPID)
		}
		if err := validateServiceChainRouteReservation(
			strings.TrimSpace(policy.ID),
			mark,
			preference,
			target.Table,
			normalizedOptions.ExistingRouteRules,
		); err != nil {
			return ServiceChainPlan{}, err
		}

		family, err := compileServiceChainSelector(policy.Selector)
		if err != nil {
			return ServiceChainPlan{}, fmt.Errorf("route %q selector: %w", strings.TrimSpace(policy.ID), err)
		}
		if err := validateServiceChainTargetFamily(target, family); err != nil {
			return ServiceChainPlan{}, fmt.Errorf("route %q target: %w", strings.TrimSpace(policy.ID), err)
		}

		routes = append(routes, ServiceChainRoute{
			RouteID:    strings.TrimSpace(policy.ID),
			ChainID:    strings.TrimSpace(policy.Chain.ID),
			NextPOPID:  nextPOPID,
			ReturnHops: append([]string(nil), policy.Chain.ReturnHops...),
			Selector:   policy.Selector,
			Family:     family,
			Mark:       mark,
			Preference: preference,
			Target:     target,
		})
	}

	plan := ServiceChainPlan{
		LocalPOPID:       normalizedOptions.LocalPOPID,
		IngressInterface: normalizedOptions.IngressInterface,
		Routes:           routes,
	}
	if err := plan.Validate(); err != nil {
		return ServiceChainPlan{}, fmt.Errorf("validate service-chain plan: %w", err)
	}
	return plan, nil
}

func (t ServiceChainTransportTarget) Validate() error {
	_, err := normalizeServiceChainTransportTarget(t)
	return err
}

func (p ServiceChainPlan) Validate() error {
	localPOPID := strings.TrimSpace(p.LocalPOPID)
	if localPOPID == "" {
		return fmt.Errorf("service-chain plan local POP id is required")
	}
	if err := validateServiceChainInterface(p.IngressInterface, "service-chain plan ingress interface"); err != nil {
		return err
	}
	if len(p.Routes) == 0 {
		return fmt.Errorf("service-chain plan must define at least one route")
	}

	marks := make(map[int]struct{}, len(p.Routes))
	preferences := make(map[int]struct{}, len(p.Routes))
	tableTargets := make(map[serviceChainRouteTableKey]ServiceChainTransportTarget, len(p.Routes))
	for index, route := range p.Routes {
		if err := validateServiceChainRoute(route, localPOPID); err != nil {
			return fmt.Errorf("service-chain route %d: %w", index, err)
		}
		if _, exists := marks[route.Mark]; exists {
			return fmt.Errorf("duplicate service-chain route mark %d", route.Mark)
		}
		marks[route.Mark] = struct{}{}
		if _, exists := preferences[route.Preference]; exists {
			return fmt.Errorf("duplicate service-chain route preference %d", route.Preference)
		}
		preferences[route.Preference] = struct{}{}

		key := serviceChainRouteTableKey{family: route.Family, table: route.Target.Table}
		if existing, exists := tableTargets[key]; exists && !sameServiceChainTarget(existing, route.Target) {
			return fmt.Errorf("service-chain routes sharing %s table %d must use the same target", route.Family, route.Target.Table)
		}
		tableTargets[key] = route.Target
	}
	return nil
}

func (p ServiceChainPlan) RenderNftables() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}

	var b strings.Builder
	b.WriteString("table inet anixops_service_chain {\n")
	b.WriteString("  chain prerouting {\n")
	fmt.Fprintf(&b, "    type filter hook prerouting priority %d; policy accept;\n", DefaultServiceChainNftPriority)
	b.WriteString("    ct state established,related meta mark set ct mark\n")
	for _, route := range p.Routes {
		fmt.Fprintf(&b, "    iifname %q ct mark 0", strings.TrimSpace(p.IngressInterface))
		if sourceCIDR := strings.TrimSpace(route.Selector.SourceCIDR); sourceCIDR != "" {
			fmt.Fprintf(&b, " %s saddr %s", nftServiceChainFamilyKeyword(route.Family), sourceCIDR)
		}
		if destinationCIDR := strings.TrimSpace(route.Selector.DestinationCIDR); destinationCIDR != "" {
			fmt.Fprintf(&b, " %s daddr %s", nftServiceChainFamilyKeyword(route.Family), destinationCIDR)
		}
		if route.Selector.Ports != nil {
			fmt.Fprintf(&b, " %s dport %d-%d", route.Selector.Protocol, route.Selector.Ports.Start, route.Selector.Ports.End)
		} else if route.Selector.Protocol != "" {
			fmt.Fprintf(&b, " meta l4proto %s", route.Selector.Protocol)
		}
		fmt.Fprintf(&b, " meta mark set %d ct mark set %d\n", route.Mark, route.Mark)
	}
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String(), nil
}

func (p ServiceChainPlan) RenderIPRouteCommands() ([]string, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	installedTables := make(map[serviceChainRouteTableKey]struct{}, len(p.Routes))
	commands := make([]string, 0, len(p.Routes)*2)
	for _, route := range p.Routes {
		key := serviceChainRouteTableKey{family: route.Family, table: route.Target.Table}
		if _, installed := installedTables[key]; !installed {
			commands = append(commands, renderServiceChainDefaultRoute(route))
			installedTables[key] = struct{}{}
		}
		commands = append(commands, renderServiceChainPolicyRule(route))
	}
	return commands, nil
}

type serviceChainRouteTableKey struct {
	family ServiceChainIPFamily
	table  int
}

func normalizeServiceChainCompileOptions(options ServiceChainCompileOptions) (ServiceChainCompileOptions, error) {
	options.LocalPOPID = strings.TrimSpace(options.LocalPOPID)
	options.IngressInterface = strings.TrimSpace(options.IngressInterface)
	options.ExistingRouteRules = append([]RouteRule(nil), options.ExistingRouteRules...)
	if options.MarkBase == 0 {
		options.MarkBase = DefaultServiceChainMarkBase
	}
	if options.PreferenceBase == 0 {
		options.PreferenceBase = DefaultServiceChainPreferenceBase
	}
	if options.LocalPOPID == "" {
		return ServiceChainCompileOptions{}, fmt.Errorf("local POP id is required")
	}
	if err := validateServiceChainInterface(options.IngressInterface, "ingress interface"); err != nil {
		return ServiceChainCompileOptions{}, err
	}
	if options.MarkBase <= 0 {
		return ServiceChainCompileOptions{}, fmt.Errorf("service-chain mark base must be positive")
	}
	if options.PreferenceBase <= 0 {
		return ServiceChainCompileOptions{}, fmt.Errorf("service-chain preference base must be positive")
	}
	for _, rule := range options.ExistingRouteRules {
		if err := rule.Validate(); err != nil {
			return ServiceChainCompileOptions{}, fmt.Errorf("existing route rule %q is invalid", strings.TrimSpace(rule.Name))
		}
	}
	return options, nil
}

func validateServiceChainRouteReservation(routeID string, mark, preference, table int, existingRouteRules []RouteRule) error {
	for _, rule := range existingRouteRules {
		existingRouteRuleID := strings.TrimSpace(rule.Name)
		if mark == rule.Mark {
			return fmt.Errorf("route %q mark %d conflicts with existing route rule %q", routeID, mark, existingRouteRuleID)
		}
		if preference == rule.Preference {
			return fmt.Errorf("route %q preference %d conflicts with existing route rule %q", routeID, preference, existingRouteRuleID)
		}
		if table == rule.Table {
			return fmt.Errorf("route %q table %d conflicts with existing route rule %q", routeID, table, existingRouteRuleID)
		}
	}
	return nil
}

func serviceChainTargetsByPOPID(targets []ServiceChainTransportTarget) (map[string]ServiceChainTransportTarget, error) {
	targetsByPOPID := make(map[string]ServiceChainTransportTarget, len(targets))
	tables := make(map[int]string, len(targets))
	for _, target := range targets {
		normalized, err := normalizeServiceChainTransportTarget(target)
		if err != nil {
			return nil, err
		}
		if _, exists := targetsByPOPID[normalized.POPID]; exists {
			return nil, fmt.Errorf("duplicate service-chain transport target POP id %q", normalized.POPID)
		}
		if previousPOPID, exists := tables[normalized.Table]; exists {
			return nil, fmt.Errorf("duplicate service-chain transport target table %d for POP ids %q and %q", normalized.Table, previousPOPID, normalized.POPID)
		}
		targetsByPOPID[normalized.POPID] = normalized
		tables[normalized.Table] = normalized.POPID
	}
	return targetsByPOPID, nil
}

func normalizeServiceChainTransportTarget(target ServiceChainTransportTarget) (ServiceChainTransportTarget, error) {
	target.POPID = strings.TrimSpace(target.POPID)
	target.Gateway = strings.TrimSpace(target.Gateway)
	target.Interface = strings.TrimSpace(target.Interface)
	if target.POPID == "" {
		return ServiceChainTransportTarget{}, fmt.Errorf("service-chain transport target POP id is required")
	}
	if target.Gateway != "" && net.ParseIP(target.Gateway) == nil {
		return ServiceChainTransportTarget{}, fmt.Errorf("service-chain transport target %q has invalid gateway", target.POPID)
	}
	if err := validateServiceChainInterface(target.Interface, fmt.Sprintf("service-chain transport target %q interface", target.POPID)); err != nil {
		return ServiceChainTransportTarget{}, err
	}
	if target.Table <= 0 {
		return ServiceChainTransportTarget{}, fmt.Errorf("service-chain transport target %q table must be positive", target.POPID)
	}
	if isReservedServiceChainRoutingTable(target.Table) {
		return ServiceChainTransportTarget{}, fmt.Errorf("service-chain transport target %q table %d is reserved", target.POPID, target.Table)
	}
	return target, nil
}

func validateServiceChainRoute(route ServiceChainRoute, localPOPID string) error {
	if strings.TrimSpace(route.RouteID) == "" {
		return fmt.Errorf("route id is required")
	}
	if strings.TrimSpace(route.ChainID) == "" {
		return fmt.Errorf("chain id is required")
	}
	if strings.TrimSpace(route.NextPOPID) == "" {
		return fmt.Errorf("next POP id is required")
	}
	if strings.TrimSpace(route.NextPOPID) == localPOPID {
		return fmt.Errorf("first hop %q is the local POP", strings.TrimSpace(route.NextPOPID))
	}
	if route.Mark <= 0 {
		return fmt.Errorf("mark must be positive")
	}
	if route.Preference <= 0 {
		return fmt.Errorf("preference must be positive")
	}

	family, err := compileServiceChainSelector(route.Selector)
	if err != nil {
		return fmt.Errorf("selector: %w", err)
	}
	if route.Family != family {
		return fmt.Errorf("selector family %q does not match route family %q", family, route.Family)
	}
	if err := validateServiceChainReturnHops(route.ReturnHops); err != nil {
		return err
	}
	target, err := normalizeServiceChainTransportTarget(route.Target)
	if err != nil {
		return err
	}
	if target.POPID != strings.TrimSpace(route.NextPOPID) {
		return fmt.Errorf("target POP id %q does not match next POP id %q", target.POPID, strings.TrimSpace(route.NextPOPID))
	}
	if err := validateServiceChainTargetFamily(target, route.Family); err != nil {
		return err
	}
	return nil
}

func validateServiceChainReturnHops(hops []string) error {
	seen := make(map[string]struct{}, len(hops))
	for _, hop := range hops {
		normalized := strings.TrimSpace(hop)
		if normalized == "" {
			return fmt.Errorf("return hop is required")
		}
		if _, exists := seen[normalized]; exists {
			return fmt.Errorf("duplicate return hop %q", normalized)
		}
		seen[normalized] = struct{}{}
	}
	return nil
}

func compileServiceChainSelector(selector controlcontract.RouteSelector) (ServiceChainIPFamily, error) {
	if err := selector.Validate(); err != nil {
		return "", err
	}
	if strings.TrimSpace(selector.DomainSuffix) != "" {
		return "", fmt.Errorf("domain suffix selectors require a classifier")
	}
	if strings.TrimSpace(selector.TrafficClass) != "" {
		return "", fmt.Errorf("traffic class selectors require a classifier")
	}

	sourceCIDR := strings.TrimSpace(selector.SourceCIDR)
	destinationCIDR := strings.TrimSpace(selector.DestinationCIDR)
	if sourceCIDR == "" && destinationCIDR == "" {
		return "", fmt.Errorf("a source or destination CIDR is required")
	}

	var family ServiceChainIPFamily
	if sourceCIDR != "" {
		parsedFamily, err := serviceChainCIDRFamily(sourceCIDR)
		if err != nil {
			return "", fmt.Errorf("invalid source CIDR: %w", err)
		}
		family = parsedFamily
	}
	if destinationCIDR != "" {
		parsedFamily, err := serviceChainCIDRFamily(destinationCIDR)
		if err != nil {
			return "", fmt.Errorf("invalid destination CIDR: %w", err)
		}
		if family != "" && family != parsedFamily {
			return "", fmt.Errorf("mixed IP families are not supported")
		}
		family = parsedFamily
	}
	return family, nil
}

func serviceChainCIDRFamily(cidr string) (ServiceChainIPFamily, error) {
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return "", err
	}
	if strings.Contains(cidr, ":") {
		return ServiceChainIPv6, nil
	}
	return ServiceChainIPv4, nil
}

func validateServiceChainTargetFamily(target ServiceChainTransportTarget, family ServiceChainIPFamily) error {
	if target.Gateway == "" {
		return nil
	}
	gatewayFamily, err := serviceChainGatewayFamily(target.Gateway)
	if err != nil {
		return err
	}
	if gatewayFamily != family {
		return fmt.Errorf("gateway %q family %s does not match route family %s", target.Gateway, gatewayFamily, family)
	}
	return nil
}

func serviceChainGatewayFamily(gateway string) (ServiceChainIPFamily, error) {
	if net.ParseIP(gateway) == nil {
		return "", fmt.Errorf("invalid gateway %q", gateway)
	}
	if strings.Contains(gateway, ":") {
		return ServiceChainIPv6, nil
	}
	return ServiceChainIPv4, nil
}

func serviceChainSequenceValue(base, index int, field string) (int, error) {
	if index < 0 || base > maximumServiceChainInt-index {
		return 0, fmt.Errorf("service-chain %s value overflows", field)
	}
	return base + index, nil
}

func validateServiceChainInterface(value, field string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if strings.ContainsAny(value, " \t\r\n\"'") {
		return fmt.Errorf("%s contains unsupported characters", field)
	}
	return nil
}

func isReservedServiceChainRoutingTable(table int) bool {
	return table == 253 || table == 254 || table == 255
}

func sameServiceChainTarget(left, right ServiceChainTransportTarget) bool {
	return strings.TrimSpace(left.POPID) == strings.TrimSpace(right.POPID) &&
		strings.TrimSpace(left.Gateway) == strings.TrimSpace(right.Gateway) &&
		strings.TrimSpace(left.Interface) == strings.TrimSpace(right.Interface) &&
		left.Table == right.Table
}

func nftServiceChainFamilyKeyword(family ServiceChainIPFamily) string {
	if family == ServiceChainIPv6 {
		return "ip6"
	}
	return "ip"
}

func renderServiceChainDefaultRoute(route ServiceChainRoute) string {
	command := "ip"
	destination := "0.0.0.0/0"
	if route.Family == ServiceChainIPv6 {
		command = "ip -6"
		destination = "::/0"
	}
	rendered := fmt.Sprintf("%s route replace %s", command, destination)
	if gateway := strings.TrimSpace(route.Target.Gateway); gateway != "" {
		rendered += " via " + gateway
	}
	rendered += " dev " + strings.TrimSpace(route.Target.Interface)
	return fmt.Sprintf("%s table %d", rendered, route.Target.Table)
}

func renderServiceChainPolicyRule(route ServiceChainRoute) string {
	command := "ip"
	if route.Family == ServiceChainIPv6 {
		command = "ip -6"
	}
	return fmt.Sprintf("%s rule add fwmark %d table %d priority %d", command, route.Mark, route.Target.Table, route.Preference)
}

const maximumServiceChainInt = int(^uint(0) >> 1)
