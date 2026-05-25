package linuxgw

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

type RouteRule struct {
	Name       string
	Mark       int
	MatchCIDR  string
	Table      int
	DestCIDR   string
	Gateway    string
	Interface  string
	Preference int
}

type Config struct {
	LANInterface         string
	LANCIDR              string
	DHCPRangeStart       string
	DHCPRangeEnd         string
	DNSListenAddress     string
	DNSUpstreams         []string
	TransparentProxyPort int
	RouteRules           []RouteRule
}

func (c Config) Validate() error {
	if c.LANInterface == "" {
		return fmt.Errorf("lan interface is required")
	}
	if _, _, err := net.ParseCIDR(c.LANCIDR); err != nil {
		return fmt.Errorf("invalid lan cidr: %w", err)
	}
	if net.ParseIP(c.DHCPRangeStart) == nil {
		return fmt.Errorf("invalid dhcp range start")
	}
	if net.ParseIP(c.DHCPRangeEnd) == nil {
		return fmt.Errorf("invalid dhcp range end")
	}
	if net.ParseIP(c.DNSListenAddress) == nil {
		return fmt.Errorf("invalid dns listen address")
	}
	if c.TransparentProxyPort <= 0 || c.TransparentProxyPort > 65535 {
		return fmt.Errorf("transparent proxy port must be between 1 and 65535")
	}
	for _, upstream := range c.DNSUpstreams {
		if net.ParseIP(upstream) == nil {
			return fmt.Errorf("invalid dns upstream %q", upstream)
		}
	}
	for _, rule := range c.RouteRules {
		if err := rule.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (r RouteRule) Validate() error {
	if r.Name == "" {
		return fmt.Errorf("route rule name is required")
	}
	if r.Mark <= 0 {
		return fmt.Errorf("route rule %q mark must be positive", r.Name)
	}
	if r.Table <= 0 {
		return fmt.Errorf("route rule %q table must be positive", r.Name)
	}
	if r.MatchCIDR != "" {
		if _, _, err := net.ParseCIDR(r.MatchCIDR); err != nil {
			return fmt.Errorf("route rule %q invalid match CIDR: %w", r.Name, err)
		}
	}
	if _, _, err := net.ParseCIDR(r.DestCIDR); err != nil {
		return fmt.Errorf("route rule %q invalid destination: %w", r.Name, err)
	}
	if r.Gateway != "" && net.ParseIP(r.Gateway) == nil {
		return fmt.Errorf("route rule %q invalid gateway", r.Name)
	}
	if r.Interface == "" {
		return fmt.Errorf("route rule %q interface is required", r.Name)
	}
	return nil
}

func (c Config) RenderNftables() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "table inet anixops {\n")
	if hasPolicyMarkRules(c.RouteRules) {
		fmt.Fprintf(&b, "  chain policy_mark {\n")
		fmt.Fprintf(&b, "    type filter hook prerouting priority mangle; policy accept;\n")
		for _, rule := range sortedRouteRules(c.RouteRules, false) {
			if rule.MatchCIDR == "" {
				continue
			}
			selector := nftCIDRSelector(rule.MatchCIDR)
			fmt.Fprintf(&b, "    iifname %q %s %s meta mark set %d\n", c.LANInterface, selector, rule.MatchCIDR, rule.Mark)
		}
		fmt.Fprintf(&b, "  }\n")
	}
	fmt.Fprintf(&b, "  chain prerouting {\n")
	fmt.Fprintf(&b, "    type nat hook prerouting priority dstnat; policy accept;\n")
	fmt.Fprintf(&b, "    iifname %q tcp dport 1-65535 redirect to %d\n", c.LANInterface, c.TransparentProxyPort)
	fmt.Fprintf(&b, "    iifname %q udp dport 1-65535 redirect to %d\n", c.LANInterface, c.TransparentProxyPort)
	fmt.Fprintf(&b, "  }\n")
	fmt.Fprintf(&b, "}\n")
	return b.String(), nil
}

func hasPolicyMarkRules(routeRules []RouteRule) bool {
	for _, rule := range routeRules {
		if strings.TrimSpace(rule.MatchCIDR) != "" {
			return true
		}
	}
	return false
}

func nftCIDRSelector(cidr string) string {
	ip, _, err := net.ParseCIDR(cidr)
	if err == nil && ip.To4() == nil {
		return "ip6 daddr"
	}
	return "ip daddr"
}

func (c Config) RenderDNSMasq() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}

	upstreams := append([]string(nil), c.DNSUpstreams...)
	sort.Strings(upstreams)

	var b strings.Builder
	fmt.Fprintf(&b, "interface=%s\n", c.LANInterface)
	fmt.Fprintf(&b, "bind-interfaces\n")
	fmt.Fprintf(&b, "listen-address=%s\n", c.DNSListenAddress)
	fmt.Fprintf(&b, "dhcp-range=%s,%s,12h\n", c.DHCPRangeStart, c.DHCPRangeEnd)
	for _, upstream := range upstreams {
		fmt.Fprintf(&b, "server=%s\n", upstream)
	}
	return b.String(), nil
}

func (c Config) RenderIPRouteCommands() ([]string, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	rules := sortedRouteRules(c.RouteRules, false)

	var commands []string
	for _, rule := range rules {
		commands = append(commands,
			fmt.Sprintf("ip rule add fwmark %d table %d priority %d", rule.Mark, rule.Table, rule.Preference),
		)
		route := fmt.Sprintf("ip route replace %s", rule.DestCIDR)
		if rule.Gateway != "" {
			route += " via " + rule.Gateway
		}
		route += " dev " + rule.Interface
		route += fmt.Sprintf(" table %d", rule.Table)
		commands = append(commands, route)
	}
	return commands, nil
}

func (c Config) RenderIPRouteRollbackCommands() ([]string, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	rules := sortedRouteRules(c.RouteRules, true)
	var commands []string
	for _, rule := range rules {
		route := fmt.Sprintf("ip route del %s", rule.DestCIDR)
		if rule.Gateway != "" {
			route += " via " + rule.Gateway
		}
		route += " dev " + rule.Interface
		route += fmt.Sprintf(" table %d", rule.Table)
		commands = append(commands, route)
		commands = append(commands,
			fmt.Sprintf("ip rule del fwmark %d table %d priority %d", rule.Mark, rule.Table, rule.Preference),
		)
	}
	return commands, nil
}

func (c Config) RenderRollbackCommands() ([]string, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	routeCommands, err := c.RenderIPRouteRollbackCommands()
	if err != nil {
		return nil, err
	}
	commands := []string{"nft delete table inet anixops"}
	commands = append(commands, routeCommands...)
	commands = append(commands, "systemctl reload dnsmasq")
	return commands, nil
}

func sortedRouteRules(routeRules []RouteRule, reverse bool) []RouteRule {
	rules := append([]RouteRule(nil), routeRules...)
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Preference == rules[j].Preference {
			if reverse {
				return rules[i].Name > rules[j].Name
			}
			return rules[i].Name < rules[j].Name
		}
		if reverse {
			return rules[i].Preference > rules[j].Preference
		}
		return rules[i].Preference < rules[j].Preference
	})
	return rules
}
