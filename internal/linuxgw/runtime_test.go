package linuxgw

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"anixops-sd-wan/internal/policy"
	"anixops-sd-wan/internal/system"
)

func TestLinuxGatewayRuntimeApplyAndRollback(t *testing.T) {
	if os.Getenv("ANIXOPS_REQUIRE_LINUXGW_RUNTIME") != "1" {
		t.Skip("linux gateway runtime verification is only required in the remote runtime gate")
	}

	ipBin := requireBinaryPath(t, "ip")
	nftBin := requireBinaryPath(t, "nft")
	dnsmasqBin := requireBinaryPath(t, "dnsmasq")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)

	ns := fmt.Sprintf("anixops-gw-%d", time.Now().UnixNano())
	runCommand(t, ctx, ipBin, "netns", "add", ns)
	t.Cleanup(func() {
		_ = exec.Command(ipBin, "netns", "del", ns).Run()
	})

	runNamespaceCommand(t, ctx, ipBin, ns, "ip", "link", "add", "lan0", "type", "dummy")
	runNamespaceCommand(t, ctx, ipBin, ns, "ip", "addr", "add", "192.168.10.1/24", "dev", "lan0")
	runNamespaceCommand(t, ctx, ipBin, ns, "ip", "link", "set", "lan0", "up")
	runNamespaceCommand(t, ctx, ipBin, ns, "ip", "link", "add", "wg-ai", "type", "dummy")
	runNamespaceCommand(t, ctx, ipBin, ns, "ip", "link", "set", "wg-ai", "up")

	tempDir := t.TempDir()
	nftPath := filepath.Join(tempDir, "anixops.nft")
	dnsmasqPath := filepath.Join(tempDir, "dnsmasq.conf")
	rewritten, err := testConfig().RenderDNSMasq()
	if err != nil {
		t.Fatalf("render dnsmasq: %v", err)
	}
	if err := os.WriteFile(dnsmasqPath, []byte(rewritten), 0o600); err != nil {
		t.Fatalf("write dnsmasq config: %v", err)
	}

	dnsCmd := exec.CommandContext(ctx, ipBin, "netns", "exec", ns, dnsmasqBin,
		"--no-daemon",
		"--conf-file="+dnsmasqPath,
	)
	var dnsmasqOutput strings.Builder
	dnsCmd.Stdout = &dnsmasqOutput
	dnsCmd.Stderr = &dnsmasqOutput
	if err := dnsCmd.Start(); err != nil {
		t.Fatalf("start dnsmasq: %v\n%s", err, dnsmasqOutput.String())
	}
	dnsmasqPID := fmt.Sprintf("%d", dnsCmd.Process.Pid)
	reloadMarker := filepath.Join(tempDir, "dnsmasq.reload")
	t.Cleanup(func() {
		if dnsCmd.Process != nil {
			_ = dnsCmd.Process.Kill()
		}
		_ = dnsCmd.Wait()
	})

	wrapperDir := filepath.Join(tempDir, "bin")
	if err := os.MkdirAll(wrapperDir, 0o755); err != nil {
		t.Fatalf("create wrapper dir: %v", err)
	}
	writeScript(t, filepath.Join(wrapperDir, "ip"), fmt.Sprintf(`#!/bin/sh
exec %q netns exec %q %q "$@"
`, ipBin, ns, ipBin))
	writeScript(t, filepath.Join(wrapperDir, "nft"), fmt.Sprintf(`#!/bin/sh
exec %q netns exec %q %q "$@"
`, ipBin, ns, nftBin))
	writeScript(t, filepath.Join(wrapperDir, "systemctl"), fmt.Sprintf(`#!/bin/sh
set -eu
case "$1 $2" in
  reload\ dnsmasq)
    %q --test -C %q >/dev/null
    printf reload > %q
    kill -HUP %s
    ;;
  *)
    exit 0
    ;;
esac
`, dnsmasqBin, dnsmasqPath, reloadMarker, dnsmasqPID))

	t.Setenv("PATH", wrapperDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ANIXOPS_DNSMASQ_CONF", dnsmasqPath)

	base := testConfig()
	base.RouteRules = nil
	classifier, err := policy.NewClassifier([]policy.ClassificationRule{{
		ID:           "ai-domain",
		Priority:     100,
		DomainSuffix: "openai.com",
		Class:        policy.ClassAI,
	}})
	if err != nil {
		t.Fatalf("new classifier: %v", err)
	}

	planned, err := ApplyObservedPolicyRoutes(ctx, base, []policy.Request{{
		TenantID: "tenant-a",
		Domain:   "api.openai.com",
		IP:       "203.0.113.10",
	}}, classifier, []policy.Rule{{
		ID:           "ai-egress",
		TenantID:     "tenant-a",
		Priority:     100,
		DomainSuffix: "openai.com",
		Class:        policy.ClassAI,
		EgressNodeID: "egress-ai",
	}}, []EgressRouteTarget{{
		NodeID:    "egress-ai",
		Interface: "wg-ai",
		Table:     202,
	}}, PolicyRoutePlanOptions{
		MarkBase:       600,
		PreferenceBase: 16000,
	}, ApplyPaths{
		NftablesPath: nftPath,
		DNSMasqPath:  dnsmasqPath,
	}, capturingRunner{}, system.OSWriter{})
	if err != nil {
		t.Fatalf("apply observed policy routes: %v\n%s", err, dnsmasqOutput.String())
	}
	if _, err := os.Stat(reloadMarker); err != nil {
		t.Fatalf("expected dnsmasq reload marker: %v", err)
	}
	if err := dnsCmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("expected dnsmasq process to remain alive after reload: %v\n%s", err, dnsmasqOutput.String())
	}
	if len(planned) != 1 || planned[0].MatchCIDR != "203.0.113.10/32" {
		t.Fatalf("unexpected planned route rules: %+v", planned)
	}

	nftRules := runNamespaceCommandOutput(t, ctx, ipBin, ns, "nft", "list", "table", "inet", "anixops")
	for _, want := range []string{
		`iifname "lan0" ip daddr 203.0.113.10 meta mark set 0x00000258`,
		`iifname "lan0" tcp dport 1-65535 redirect to :12345`,
		`iifname "lan0" udp dport 1-65535 redirect to :12345`,
	} {
		if !strings.Contains(nftRules, want) {
			t.Fatalf("expected nft table to contain %q:\n%s", want, nftRules)
		}
	}

	ipRules := runNamespaceCommandOutput(t, ctx, ipBin, ns, "ip", "rule", "show")
	for _, want := range []string{
		"lookup 202",
		"16000",
	} {
		if !strings.Contains(ipRules, want) {
			t.Fatalf("expected ip rule output to contain %q:\n%s", want, ipRules)
		}
	}
	ipRoutes := runNamespaceCommandOutput(t, ctx, ipBin, ns, "ip", "route", "show", "table", "202")
	if !strings.Contains(ipRoutes, "default dev wg-ai") {
		t.Fatalf("expected route table to contain default dev wg-ai:\n%s", ipRoutes)
	}

	next := base
	next.RouteRules = append([]RouteRule(nil), planned...)
	if err := next.Rollback(ctx, capturingRunner{}); err != nil {
		t.Fatalf("rollback applied config: %v", err)
	}
	ipRulesAfter := runNamespaceCommandOutput(t, ctx, ipBin, ns, "ip", "rule", "show")
	if strings.Contains(ipRulesAfter, "lookup 202") {
		t.Fatalf("expected route rule to be removed after rollback:\n%s", ipRulesAfter)
	}
	if out, err := runNamespaceCommand(t, ctx, ipBin, ns, "nft", "list", "table", "inet", "anixops"); err == nil {
		t.Fatalf("expected nft table to be removed after rollback, got:\n%s", out)
	}
}

func TestLinuxGatewayRuntimeLiveDNSObservationAndRouteApplication(t *testing.T) {
	if os.Getenv("ANIXOPS_REQUIRE_LINUXGW_RUNTIME") != "1" {
		t.Skip("linux gateway runtime verification is only required in the remote runtime gate")
	}

	ipBin := requireBinaryPath(t, "ip")
	nftBin := requireBinaryPath(t, "nft")
	dnsmasqBin := requireBinaryPath(t, "dnsmasq")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)

	ns := fmt.Sprintf("anixops-gw-dns-%d", time.Now().UnixNano())
	runCommand(t, ctx, ipBin, "netns", "add", ns)
	t.Cleanup(func() {
		_ = exec.Command(ipBin, "netns", "del", ns).Run()
	})

	runCommand(t, ctx, ipBin, "link", "add", "lan0-host", "type", "veth", "peer", "name", "lan0")
	runCommand(t, ctx, ipBin, "link", "set", "lan0", "netns", ns)
	runCommand(t, ctx, ipBin, "addr", "add", "192.168.10.2/24", "dev", "lan0-host")
	runCommand(t, ctx, ipBin, "link", "set", "lan0-host", "up")
	runNamespaceCommand(t, ctx, ipBin, ns, "ip", "addr", "add", "192.168.10.1/24", "dev", "lan0")
	runNamespaceCommand(t, ctx, ipBin, ns, "ip", "link", "set", "lan0", "up")
	runNamespaceCommand(t, ctx, ipBin, ns, "ip", "link", "add", "wg-ai", "type", "dummy")
	runNamespaceCommand(t, ctx, ipBin, ns, "ip", "link", "set", "wg-ai", "up")

	tempDir := t.TempDir()
	nftPath := filepath.Join(tempDir, "anixops.nft")
	dnsmasqPath := filepath.Join(tempDir, "dnsmasq.conf")
	dnsmasqLog := filepath.Join(tempDir, "dnsmasq.log")

	rewritten, err := testConfig().RenderDNSMasq()
	if err != nil {
		t.Fatalf("render dnsmasq: %v", err)
	}
	rewritten += strings.Join([]string{
		"port=5353",
		"log-queries",
		"log-facility=" + dnsmasqLog,
		"address=/api.openai.com/203.0.113.10",
	}, "\n") + "\n"
	if err := os.WriteFile(dnsmasqPath, []byte(rewritten), 0o600); err != nil {
		t.Fatalf("write dnsmasq config: %v", err)
	}

	dnsCmd := exec.CommandContext(ctx, ipBin, "netns", "exec", ns, dnsmasqBin,
		"--no-daemon",
		"--conf-file="+dnsmasqPath,
	)
	var dnsmasqOutput strings.Builder
	dnsCmd.Stdout = &dnsmasqOutput
	dnsCmd.Stderr = &dnsmasqOutput
	if err := dnsCmd.Start(); err != nil {
		t.Fatalf("start dnsmasq: %v\n%s", err, dnsmasqOutput.String())
	}
	t.Cleanup(func() {
		if dnsCmd.Process != nil {
			_ = dnsCmd.Process.Kill()
		}
		_ = dnsCmd.Wait()
	})

	wrapperDir := filepath.Join(tempDir, "bin")
	if err := os.MkdirAll(wrapperDir, 0o755); err != nil {
		t.Fatalf("create wrapper dir: %v", err)
	}
	writeScript(t, filepath.Join(wrapperDir, "ip"), fmt.Sprintf(`#!/bin/sh
exec %q netns exec %q %q "$@"
`, ipBin, ns, ipBin))
	writeScript(t, filepath.Join(wrapperDir, "nft"), fmt.Sprintf(`#!/bin/sh
exec %q netns exec %q %q "$@"
`, ipBin, ns, nftBin))
	writeScript(t, filepath.Join(wrapperDir, "systemctl"), fmt.Sprintf(`#!/bin/sh
set -eu
case "$1 $2" in
  reload\ dnsmasq)
    %q --test -C %q >/dev/null
    printf reload > %q
    kill -HUP %d
    ;;
  *)
    exit 0
    ;;
esac
`, dnsmasqBin, dnsmasqPath, filepath.Join(tempDir, "dnsmasq.reload"), dnsCmd.Process.Pid))

	t.Setenv("PATH", wrapperDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("ANIXOPS_DNSMASQ_CONF", dnsmasqPath)

	waitForDNSResolution(t, ctx, "192.168.10.1:5353", "api.openai.com", "203.0.113.10")
	waitForFile(t, dnsmasqLog, 10*time.Second)

	logData := waitForDNSMasqLogObservation(t, dnsmasqLog, "tenant-a", "api.openai.com", "203.0.113.10")

	base := testConfig()
	base.RouteRules = nil
	classifier, err := policy.NewClassifier([]policy.ClassificationRule{{
		ID:           "ai-domain",
		Priority:     100,
		DomainSuffix: "openai.com",
		Class:        policy.ClassAI,
	}})
	if err != nil {
		t.Fatalf("new classifier: %v", err)
	}

	planned, err := ApplyDNSMasqObservedPolicyRoutes(ctx, base, "tenant-a", strings.NewReader(logData), classifier, []policy.Rule{{
		ID:           "ai-egress",
		TenantID:     "tenant-a",
		Priority:     100,
		DomainSuffix: "openai.com",
		Class:        policy.ClassAI,
		EgressNodeID: "egress-ai",
	}}, []EgressRouteTarget{{
		NodeID:    "egress-ai",
		Interface: "wg-ai",
		Table:     202,
	}}, PolicyRoutePlanOptions{
		MarkBase:       600,
		PreferenceBase: 16000,
	}, ApplyPaths{
		NftablesPath: nftPath,
		DNSMasqPath:  dnsmasqPath,
	}, capturingRunner{}, system.OSWriter{})
	if err != nil {
		t.Fatalf("apply live dnsmasq observed policy routes: %v\n%s", err, dnsmasqOutput.String())
	}
	if len(planned) != 1 || planned[0].MatchCIDR != "203.0.113.10/32" {
		t.Fatalf("unexpected planned route rules: %+v", planned)
	}

	nftRules := runNamespaceCommandOutput(t, ctx, ipBin, ns, "nft", "list", "table", "inet", "anixops")
	for _, want := range []string{
		`iifname "lan0" ip daddr 203.0.113.10 meta mark set 0x00000258`,
		`iifname "lan0" tcp dport 1-65535 redirect to :12345`,
		`iifname "lan0" udp dport 1-65535 redirect to :12345`,
	} {
		if !strings.Contains(nftRules, want) {
			t.Fatalf("expected nft table to contain %q:\n%s", want, nftRules)
		}
	}

	ipRules := runNamespaceCommandOutput(t, ctx, ipBin, ns, "ip", "rule", "show")
	for _, want := range []string{
		"lookup 202",
		"16000",
	} {
		if !strings.Contains(ipRules, want) {
			t.Fatalf("expected ip rule output to contain %q:\n%s", want, ipRules)
		}
	}
	ipRoutes := runNamespaceCommandOutput(t, ctx, ipBin, ns, "ip", "route", "show", "table", "202")
	if !strings.Contains(ipRoutes, "default dev wg-ai") {
		t.Fatalf("expected route table to contain default dev wg-ai:\n%s", ipRoutes)
	}
}

func requireBinaryPath(t *testing.T, name string) string {
	t.Helper()

	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("required binary %q not found: %v", name, err)
	}
	return path
}

func runCommand(t *testing.T, ctx context.Context, name string, args ...string) {
	t.Helper()

	cmd := exec.CommandContext(ctx, name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run %s %v: %v\n%s", name, args, err, out)
	}
}

func runNamespaceCommand(t *testing.T, ctx context.Context, ipBin, ns string, name string, args ...string) (string, error) {
	t.Helper()

	fullArgs := append([]string{"netns", "exec", ns, name}, args...)
	cmd := exec.CommandContext(ctx, ipBin, fullArgs...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func runNamespaceCommandOutput(t *testing.T, ctx context.Context, ipBin, ns string, name string, args ...string) string {
	t.Helper()

	out, err := runNamespaceCommand(t, ctx, ipBin, ns, name, args...)
	if err != nil {
		t.Fatalf("run namespace command %s %v: %v\n%s", name, args, err, out)
	}
	return out
}

func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

func writeScript(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write script %s: %v", path, err)
	}
}

func waitForDNSResolution(t *testing.T, ctx context.Context, address, domain, wantIP string) {
	t.Helper()

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 2 * time.Second}
			return dialer.DialContext(ctx, "udp", address)
		},
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		records, err := resolver.LookupIPAddr(ctx, domain)
		if err == nil {
			for _, record := range records {
				if record.IP.String() == wantIP {
					return
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s to resolve to %s via %s", domain, wantIP, address)
}

func waitForDNSMasqLogObservation(t *testing.T, logPath, tenantID, wantDomain, wantIP string) string {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(logPath)
		if err == nil {
			observations, parseErr := ParseDNSMasqLogObservations(tenantID, strings.NewReader(string(data)))
			if parseErr == nil {
				for _, request := range observations {
					if request.Domain == wantDomain && request.IP == wantIP {
						return string(data)
					}
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	data, _ := os.ReadFile(logPath)
	t.Fatalf("timed out waiting for dnsmasq observation %s -> %s:\n%s", wantDomain, wantIP, string(data))
	return ""
}

type capturingRunner struct{}

func (capturingRunner) Run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w\n%s", name, args, err, out)
	}
	return nil
}
