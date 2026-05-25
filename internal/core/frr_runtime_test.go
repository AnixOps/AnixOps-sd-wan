package core

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestFRRRuntimeSessionAndRouteWithdrawal(t *testing.T) {
	if os.Getenv("ANIXOPS_REQUIRE_FRR_RUNTIME") != "1" {
		t.Skip("frr runtime verification is only required in the remote runtime gate")
	}

	ipBin := requireCommandPath(t, "ip")
	bgpdBin := requireCommandPath(t, "/usr/lib/frr/bgpd", "bgpd")
	vtyshBin := requireCommandPath(t, "/usr/bin/vtysh", "vtysh")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	tempDir := t.TempDir()
	nsA := fmt.Sprintf("anixops-frr-a-%d", time.Now().UnixNano())
	nsB := fmt.Sprintf("anixops-frr-b-%d", time.Now().UnixNano())
	ensureNetns(t, ctx, ipBin, nsA)
	ensureNetns(t, ctx, ipBin, nsB)
	t.Cleanup(func() {
		_ = exec.Command(ipBin, "netns", "del", nsA).Run()
		_ = exec.Command(ipBin, "netns", "del", nsB).Run()
	})

	runCommand(t, ctx, ipBin, "link", "add", "veth-a", "type", "veth", "peer", "name", "veth-b")
	runCommand(t, ctx, ipBin, "link", "set", "veth-a", "netns", nsA)
	runCommand(t, ctx, ipBin, "link", "set", "veth-b", "netns", nsB)
	runNamespaceCommand(t, ctx, ipBin, nsA, "ip", "addr", "add", "10.200.0.1/24", "dev", "veth-a")
	runNamespaceCommand(t, ctx, ipBin, nsA, "ip", "link", "set", "veth-a", "up")
	runNamespaceCommand(t, ctx, ipBin, nsB, "ip", "addr", "add", "10.200.0.2/24", "dev", "veth-b")
	runNamespaceCommand(t, ctx, ipBin, nsB, "ip", "link", "set", "veth-b", "up")

	cfgA := filepath.Join(tempDir, "bgpd-a.conf")
	cfgB := filepath.Join(tempDir, "bgpd-b.conf")
	pidA := filepath.Join(tempDir, "bgpd-a.pid")
	pidB := filepath.Join(tempDir, "bgpd-b.pid")
	pathspaceA := "anixops-frr-a"
	pathspaceB := "anixops-frr-b"
	if err := os.WriteFile(cfgA, []byte(strings.TrimSpace(`
hostname anixops-frr-a
router bgp 65001
 bgp router-id 10.255.0.1
 timers bgp 1 3
 no bgp ebgp-requires-policy
 no bgp network import-check
 neighbor 10.200.0.2 remote-as 65002
 address-family ipv4 unicast
  network 10.10.0.0/24
  neighbor 10.200.0.2 activate
 exit-address-family
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write bgpd config A: %v", err)
	}
	if err := os.WriteFile(cfgB, []byte(strings.TrimSpace(`
hostname anixops-frr-b
router bgp 65002
 bgp router-id 10.255.0.2
 timers bgp 1 3
 no bgp ebgp-requires-policy
 no bgp network import-check
 neighbor 10.200.0.1 remote-as 65001
 address-family ipv4 unicast
  neighbor 10.200.0.1 activate
 exit-address-family
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write bgpd config B: %v", err)
	}

	startBgpd(t, ctx, ipBin, nsA, bgpdBin, cfgA, pathspaceA, pidA)
	startBgpd(t, ctx, ipBin, nsB, bgpdBin, cfgB, pathspaceB, pidB)

	waitForVtyshOutputContains(t, ctx, vtyshBin, pathspaceA, "show bgp neighbors 10.200.0.2", "BGP state = Established")
	waitForVtyshOutputContains(t, ctx, vtyshBin, pathspaceB, "show bgp neighbors 10.200.0.1", "BGP state = Established")
	waitForVtyshOutputContains(t, ctx, vtyshBin, pathspaceB, "show bgp ipv4 unicast", "10.10.0.0/24")

	killPidFile(t, pidA)
	waitForVtyshOutputNotContains(t, ctx, vtyshBin, pathspaceB, "show bgp neighbors 10.200.0.1", "BGP state = Established")
	waitForVtyshOutputNotContains(t, ctx, vtyshBin, pathspaceB, "show bgp ipv4 unicast", "10.10.0.0/24")
}

func requireCommandPath(t *testing.T, candidates ...string) string {
	t.Helper()

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if filepath.IsAbs(candidate) {
			if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
				return candidate
			}
			continue
		}
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	t.Fatalf("required command not found in candidates: %v", candidates)
	return ""
}

func ensureNetns(t *testing.T, ctx context.Context, ipBin, ns string) {
	t.Helper()

	_ = exec.Command(ipBin, "netns", "del", ns).Run()
	runCommand(t, ctx, ipBin, "netns", "add", ns)
}

func startBgpd(t *testing.T, ctx context.Context, ipBin, ns, bgpdBin, configPath, pathspace, pidFile string) {
	t.Helper()

	cmd := exec.CommandContext(ctx, ipBin, "netns", "exec", ns, bgpdBin,
		"-d",
		"-f", configPath,
		"-N", pathspace,
		"-i", pidFile,
		"-Z",
		"-n",
		"-S",
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start bgpd in %s: %v", ns, err)
	}
	go func() {
		_ = cmd.Wait()
	}()
	waitForFile(t, pidFile, 10*time.Second)
}

func waitForVtyshOutputContains(t *testing.T, ctx context.Context, vtyshBin, pathspace, command, want string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, err := runVtysh(t, ctx, vtyshBin, pathspace, command)
		if err == nil && strings.Contains(out, want) {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	out, _ := runVtysh(t, ctx, vtyshBin, pathspace, command)
	t.Fatalf("timed out waiting for %q in %s output:\n%s", want, command, out)
}

func waitForVtyshOutputNotContains(t *testing.T, ctx context.Context, vtyshBin, pathspace, command, want string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, err := runVtysh(t, ctx, vtyshBin, pathspace, command)
		if err == nil && !strings.Contains(out, want) {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	out, _ := runVtysh(t, ctx, vtyshBin, pathspace, command)
	t.Fatalf("timed out waiting for %q to disappear from %s output:\n%s", want, command, out)
}

func runVtysh(t *testing.T, ctx context.Context, vtyshBin, pathspace, command string) (string, error) {
	t.Helper()

	cmd := exec.CommandContext(ctx, vtyshBin, "-N", pathspace, "-d", "bgpd", "-c", command)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func killPidFile(t *testing.T, pidFile string) {
	t.Helper()

	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read pid file %s: %v", pidFile, err)
	}
	pid := strings.TrimSpace(string(data))
	if pid == "" {
		t.Fatalf("empty pid file %s", pidFile)
	}
	proc, err := os.FindProcess(parsePID(t, pid))
	if err != nil {
		t.Fatalf("find process %s: %v", pid, err)
	}
	if err := proc.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("signal pid %s: %v", pid, err)
	}
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

func parsePID(t *testing.T, value string) int {
	t.Helper()

	pid, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		t.Fatalf("parse pid %q: %v", value, err)
	}
	return pid
}
