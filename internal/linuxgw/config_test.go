package linuxgw

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"anixops-sd-wan/internal/policy"
)

func testConfig() Config {
	return Config{
		LANInterface:         "lan0",
		LANCIDR:              "192.168.10.1/24",
		DHCPRangeStart:       "192.168.10.100",
		DHCPRangeEnd:         "192.168.10.200",
		DNSListenAddress:     "192.168.10.1",
		DNSUpstreams:         []string{"1.1.1.1", "8.8.8.8"},
		TransparentProxyPort: 12345,
		RouteRules: []RouteRule{{
			Name:       "ai",
			Mark:       100,
			Table:      100,
			DestCIDR:   "0.0.0.0/0",
			Gateway:    "10.0.0.1",
			Interface:  "wg-ai",
			Preference: 1000,
		}},
	}
}

func TestRenderNftablesTransparentProxy(t *testing.T) {
	rendered, err := testConfig().RenderNftables()
	if err != nil {
		t.Fatalf("render nftables: %v", err)
	}

	for _, want := range []string{
		"table inet anixops",
		"iifname \"lan0\" tcp dport 1-65535 redirect to 12345",
		"iifname \"lan0\" udp dport 1-65535 redirect to 12345",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("expected nftables config to contain %q:\n%s", want, rendered)
		}
	}
}

func TestRenderNftablesPolicyMarksCIDRRouteRules(t *testing.T) {
	config := testConfig()
	config.RouteRules = []RouteRule{
		{
			Name:       "aws-ipv4",
			Mark:       200,
			MatchCIDR:  "203.0.113.0/24",
			Table:      200,
			DestCIDR:   "0.0.0.0/0",
			Interface:  "wg-a",
			Preference: 1000,
		},
		{
			Name:       "v6",
			Mark:       201,
			MatchCIDR:  "2001:db8::/32",
			Table:      201,
			DestCIDR:   "::/0",
			Interface:  "wg-v6",
			Preference: 1001,
		},
	}
	rendered, err := config.RenderNftables()
	if err != nil {
		t.Fatalf("render nftables: %v", err)
	}
	for _, want := range []string{
		"chain policy_mark",
		"type filter hook prerouting priority mangle; policy accept;",
		"iifname \"lan0\" ip daddr 203.0.113.0/24 meta mark set 200",
		"iifname \"lan0\" ip6 daddr 2001:db8::/32 meta mark set 201",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("expected nftables config to contain %q:\n%s", want, rendered)
		}
	}
}

func TestRenderDNSMasqDHCPAndDNS(t *testing.T) {
	rendered, err := testConfig().RenderDNSMasq()
	if err != nil {
		t.Fatalf("render dnsmasq: %v", err)
	}

	for _, want := range []string{
		"interface=lan0",
		"listen-address=192.168.10.1",
		"dhcp-range=192.168.10.100,192.168.10.200,12h",
		"server=1.1.1.1",
		"server=8.8.8.8",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("expected dnsmasq config to contain %q:\n%s", want, rendered)
		}
	}
}

func TestRenderIPRouteCommands(t *testing.T) {
	commands, err := testConfig().RenderIPRouteCommands()
	if err != nil {
		t.Fatalf("render ip route commands: %v", err)
	}

	want := []string{
		"ip rule add fwmark 100 table 100 priority 1000",
		"ip route replace 0.0.0.0/0 via 10.0.0.1 dev wg-ai table 100",
	}
	if len(commands) != len(want) {
		t.Fatalf("expected %d commands, got %d: %+v", len(want), len(commands), commands)
	}
	for i := range want {
		if commands[i] != want[i] {
			t.Fatalf("command %d expected %q, got %q", i, want[i], commands[i])
		}
	}
}

func TestRenderRollbackCommands(t *testing.T) {
	config := testConfig()
	config.RouteRules = append(config.RouteRules, RouteRule{
		Name:       "video",
		Mark:       101,
		Table:      101,
		DestCIDR:   "0.0.0.0/0",
		Interface:  "wg-video",
		Preference: 900,
	})
	commands, err := config.RenderRollbackCommands()
	if err != nil {
		t.Fatalf("render rollback commands: %v", err)
	}

	want := []string{
		"nft delete table inet anixops",
		"ip route del 0.0.0.0/0 via 10.0.0.1 dev wg-ai table 100",
		"ip rule del fwmark 100 table 100 priority 1000",
		"ip route del 0.0.0.0/0 dev wg-video table 101",
		"ip rule del fwmark 101 table 101 priority 900",
		"systemctl reload dnsmasq",
	}
	if len(commands) != len(want) {
		t.Fatalf("expected %d rollback commands, got %+v", len(want), commands)
	}
	for i := range want {
		if commands[i] != want[i] {
			t.Fatalf("rollback command %d expected %q, got %q", i, want[i], commands[i])
		}
	}
}

func TestApplyWritesConfigsAndRunsCommands(t *testing.T) {
	runner := &recordingRunner{}
	writer := newRecordingWriter()

	if err := testConfig().Apply(context.Background(), ApplyPaths{
		NftablesPath: "/tmp/anixops.nft",
		DNSMasqPath:  "/tmp/anixops-dnsmasq.conf",
	}, runner, writer); err != nil {
		t.Fatalf("apply config: %v", err)
	}

	if _, ok := writer.files["/tmp/anixops.nft"]; !ok {
		t.Fatal("expected nftables file to be written")
	}
	if _, ok := writer.files["/tmp/anixops-dnsmasq.conf"]; !ok {
		t.Fatal("expected dnsmasq file to be written")
	}
	wantFirst := recordedCommand{name: "nft", args: []string{"-f", "/tmp/anixops.nft"}}
	if len(runner.commands) < 3 {
		t.Fatalf("expected at least three commands, got %+v", runner.commands)
	}
	if !sameCommand(runner.commands[0], wantFirst) {
		t.Fatalf("expected first command %+v, got %+v", wantFirst, runner.commands[0])
	}
	if runner.commands[len(runner.commands)-1].name != "systemctl" {
		t.Fatalf("expected final command to reload dnsmasq, got %+v", runner.commands)
	}
}

func TestApplyWithRollbackRunsRollbackOnRouteFailure(t *testing.T) {
	routeErr := errors.New("route failed")
	runner := &recordingRunner{errors: map[string]error{
		"ip route replace 0.0.0.0/0 via 10.0.0.1 dev wg-ai table 100": routeErr,
	}}
	writer := newRecordingWriter()

	err := testConfig().ApplyWithRollback(context.Background(), ApplyPaths{
		NftablesPath: "/tmp/anixops.nft",
		DNSMasqPath:  "/tmp/anixops-dnsmasq.conf",
	}, runner, writer)
	if err == nil {
		t.Fatal("expected route failure")
	}
	if !strings.Contains(err.Error(), routeErr.Error()) {
		t.Fatalf("expected route failure in error, got %v", err)
	}

	got := commandStrings(runner.commands)
	wantSuffix := []string{
		"nft delete table inet anixops",
		"ip route del 0.0.0.0/0 via 10.0.0.1 dev wg-ai table 100",
		"ip rule del fwmark 100 table 100 priority 1000",
		"systemctl reload dnsmasq",
	}
	if len(got) < len(wantSuffix) {
		t.Fatalf("expected rollback commands, got %+v", got)
	}
	gotSuffix := got[len(got)-len(wantSuffix):]
	for i := range wantSuffix {
		if gotSuffix[i] != wantSuffix[i] {
			t.Fatalf("rollback command %d expected %q, got %q; all commands=%+v", i, wantSuffix[i], gotSuffix[i], got)
		}
	}
}

func TestPlanPolicyRouteRulesMapsPoliciesToEgressTargets(t *testing.T) {
	rules, err := PlanPolicyRouteRules([]policy.Rule{
		{
			ID:           "ai",
			TenantID:     "tenant-a",
			Priority:     100,
			Class:        policy.ClassAI,
			EgressNodeID: "egress-b",
		},
		{
			ID:           "video",
			TenantID:     "tenant-a",
			Priority:     50,
			IPCIDR:       "198.51.100.0/24",
			EgressNodeID: "egress-a",
		},
	}, []EgressRouteTarget{
		{NodeID: "egress-a", Gateway: "10.0.0.1", Interface: "wg-a", Table: 201},
		{NodeID: "egress-b", Gateway: "10.0.0.2", Interface: "wg-b", Table: 202},
	}, PolicyRoutePlanOptions{
		MarkBase:       200,
		PreferenceBase: 1000,
		DestCIDR:       "0.0.0.0/0",
	})
	if err != nil {
		t.Fatalf("plan policy route rules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected two route rules, got %+v", rules)
	}
	if rules[0].Name != "policy-ai" || rules[0].Mark != 200 || rules[0].Table != 202 || rules[0].Preference != 1000 {
		t.Fatalf("unexpected first route rule: %+v", rules[0])
	}
	if rules[1].Name != "policy-video" || rules[1].Mark != 201 || rules[1].Table != 201 || rules[1].Preference != 1001 {
		t.Fatalf("unexpected second route rule: %+v", rules[1])
	}
	if rules[1].MatchCIDR != "198.51.100.0/24" {
		t.Fatalf("expected IP policy to carry nft mark CIDR, got %+v", rules[1])
	}

	config := testConfig()
	config.RouteRules = rules
	commands, err := config.RenderIPRouteCommands()
	if err != nil {
		t.Fatalf("render policy route commands: %v", err)
	}
	if len(commands) != 4 {
		t.Fatalf("expected four commands, got %+v", commands)
	}
	if commands[0] != "ip rule add fwmark 200 table 202 priority 1000" {
		t.Fatalf("unexpected first command: %q", commands[0])
	}
	if commands[2] != "ip rule add fwmark 201 table 201 priority 1001" {
		t.Fatalf("unexpected third command: %q", commands[2])
	}
}

func TestPlanPolicyRouteRulesRejectsUnknownEgressNode(t *testing.T) {
	_, err := PlanPolicyRouteRules([]policy.Rule{{
		ID:           "ai",
		TenantID:     "tenant-a",
		Priority:     100,
		Class:        policy.ClassAI,
		EgressNodeID: "egress-missing",
	}}, []EgressRouteTarget{{NodeID: "egress-a", Gateway: "10.0.0.1", Interface: "wg-a", Table: 201}}, PolicyRoutePlanOptions{})
	if err == nil {
		t.Fatal("expected unknown egress node to be rejected")
	}
}

type recordedCommand struct {
	name string
	args []string
}

type recordingRunner struct {
	commands []recordedCommand
	errors   map[string]error
}

func (r *recordingRunner) Run(ctx context.Context, name string, args ...string) error {
	command := recordedCommand{name: name, args: append([]string(nil), args...)}
	r.commands = append(r.commands, command)
	if r.errors != nil {
		if err := r.errors[command.String()]; err != nil {
			return err
		}
	}
	return nil
}

func (c recordedCommand) String() string {
	return strings.TrimSpace(c.name + " " + strings.Join(c.args, " "))
}

type recordingWriter struct {
	files map[string][]byte
	perms map[string]os.FileMode
}

func newRecordingWriter() *recordingWriter {
	return &recordingWriter{
		files: make(map[string][]byte),
		perms: make(map[string]os.FileMode),
	}
}

func (w *recordingWriter) WriteFile(path string, data []byte, perm os.FileMode) error {
	w.files[path] = append([]byte(nil), data...)
	w.perms[path] = perm
	return nil
}

func sameCommand(a, b recordedCommand) bool {
	if a.name != b.name || len(a.args) != len(b.args) {
		return false
	}
	for i := range a.args {
		if a.args[i] != b.args[i] {
			return false
		}
	}
	return true
}

func commandStrings(commands []recordedCommand) []string {
	result := make([]string, 0, len(commands))
	for _, command := range commands {
		result = append(result, command.String())
	}
	return result
}
