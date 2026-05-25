package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"anixops-sd-wan/internal/config"
	"anixops-sd-wan/internal/domain"
	"anixops-sd-wan/internal/system"
)

func TestLocalConfigCacheAndRestartRecovery(t *testing.T) {
	if os.Getenv("ANIXOPS_REQUIRE_AGENT_RECOVERY_RUNTIME") != "1" {
		t.Skip("agent restart recovery verification is only required in the remote runtime gate")
	}

	if _, err := exec.LookPath("systemctl"); err != nil {
		t.Skip("systemd is required for restart recovery verification")
	}

	agentBin := buildBinary(t, "./cmd/anix-agent")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	workDir := t.TempDir()
	cachePath := filepath.Join(workDir, "cache.json")
	cache, err := NewFileConfigCache(cachePath)
	if err != nil {
		t.Fatalf("new config cache: %v", err)
	}
	bundle := domain.ConfigBundle{
		ID:       "cached-bundle",
		TenantID: config.Default().Agent.TenantID,
		TargetID: config.Default().Agent.DeviceID,
		Version:  "cached-v1",
		Values: map[string]string{
			"transport": "reality",
		},
		CreatedAt: time.Now().UTC(),
	}
	if err := cache.Save(bundle); err != nil {
		t.Fatalf("save config cache: %v", err)
	}

	apiPort := freeTCPPort(t)
	apiAddr := fmt.Sprintf("127.0.0.1:%d", apiPort)
	serviceName := fmt.Sprintf("anixops-cache-recovery-%d", time.Now().UnixNano())
	spec := system.ServiceSpec{
		Name:        serviceName,
		DisplayName: "AnixOps Agent Cache Recovery",
		Description: "AnixOps Agent cache recovery runtime gate",
		ExecPath:    agentBin,
		Args: []string{
			"--local-api-addr", apiAddr,
			"--cache-file", cachePath,
		},
		WorkingDir: workDir,
	}
	plan, err := system.RenderServiceInstallPlan(system.ServicePlatformLinux, spec)
	if err != nil {
		t.Fatalf("render service plan: %v", err)
	}
	unitPath := filepath.Join("/etc/systemd/system", serviceName+".service")
	t.Cleanup(func() {
		_ = exec.Command("systemctl", "stop", serviceName).Run()
		_ = exec.Command("systemctl", "disable", serviceName).Run()
		_ = os.Remove(unitPath)
		_ = exec.Command("systemctl", "daemon-reload").Run()
	})
	if err := plan.Apply(ctx, system.OSWriter{}, system.ExecRunner{}); err != nil {
		t.Fatalf("apply service plan: %v", err)
	}

	waitForHTTPStatus(t, ctx, "http://"+apiAddr+"/healthz", http.StatusOK)
	snapshot1 := waitForAgentSnapshot(t, ctx, apiAddr)
	if snapshot1.ConfigVersion != bundle.Version {
		t.Fatalf("expected cached config version %q on initial start, got %+v", bundle.Version, snapshot1)
	}
	mainPID1 := waitForSystemdMainPID(t, ctx, serviceName)
	if mainPID1 <= 0 {
		t.Fatalf("expected main pid on initial start, got %d", mainPID1)
	}

	if err := exec.Command("systemctl", "kill", "--signal=SIGKILL", serviceName).Run(); err != nil {
		t.Fatalf("kill service: %v", err)
	}

	mainPID2 := waitForSystemdMainPIDChange(t, ctx, serviceName, mainPID1)
	if mainPID2 <= 0 || mainPID2 == mainPID1 {
		t.Fatalf("expected restarted main pid, got %d -> %d", mainPID1, mainPID2)
	}
	waitForHTTPStatus(t, ctx, "http://"+apiAddr+"/healthz", http.StatusOK)
	snapshot2 := waitForAgentSnapshot(t, ctx, apiAddr)
	if snapshot2.ConfigVersion != bundle.Version {
		t.Fatalf("expected cached config version %q after restart, got %+v", bundle.Version, snapshot2)
	}
	if !snapshot2.Running {
		t.Fatalf("expected restarted service to be running, got %+v", snapshot2)
	}
}

func waitForHTTPStatus(t *testing.T, ctx context.Context, url string, want int) {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		resp, err := client.Do(req)
		if err == nil && resp != nil {
			_ = resp.Body.Close()
			if resp.StatusCode == want {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s status %d", url, want)
}

func waitForAgentSnapshot(t *testing.T, ctx context.Context, addr string) Snapshot {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(20 * time.Second)
	url := "http://" + addr + "/v1/snapshot"
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		var snapshot Snapshot
		decodeErr := json.NewDecoder(resp.Body).Decode(&snapshot)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK && decodeErr == nil {
			return snapshot
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for agent snapshot at %s", url)
	return Snapshot{}
}

func waitForSystemdMainPID(t *testing.T, ctx context.Context, unit string) int {
	t.Helper()
	return waitForSystemdPID(t, ctx, unit, 0)
}

func waitForSystemdMainPIDChange(t *testing.T, ctx context.Context, unit string, previous int) int {
	t.Helper()
	return waitForSystemdPID(t, ctx, unit, previous)
}

func waitForSystemdPID(t *testing.T, ctx context.Context, unit string, previous int) int {
	t.Helper()

	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		cmd := exec.CommandContext(ctx, "systemctl", "show", unit, "-p", "MainPID", "--value")
		out, err := cmd.CombinedOutput()
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		pid := strings.TrimSpace(string(out))
		if pid == "" || pid == "0" {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		var parsed int
		if _, err := fmt.Sscanf(pid, "%d", &parsed); err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if parsed > 0 && parsed != previous {
			return parsed
		}
		time.Sleep(200 * time.Millisecond)
	}
	if previous == 0 {
		t.Fatalf("timed out waiting for systemd unit %s main pid", unit)
	}
	t.Fatalf("timed out waiting for systemd unit %s main pid change from %d", unit, previous)
	return 0
}

func buildBinary(t *testing.T, pkg string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, filepath.Base(pkg))
	cmd := exec.Command("go", "build", "-o", path, pkg)
	cmd.Dir = filepath.Join("..", "..")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, output)
	}
	return path
}

func freeTCPPort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate tcp port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
