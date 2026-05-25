package core

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestWireGuardNodeRenderConfig(t *testing.T) {
	rendered, err := WireGuardNode{
		Name:       "hk-core",
		PrivateKey: "private-key",
		ListenPort: 51820,
		Address:    "10.10.0.1/24",
		Peers: []WireGuardPeer{{
			Name:       "jp-core",
			PublicKey:  "public-key",
			Endpoint:   "jp.example.com:51820",
			AllowedIPs: []string{"10.10.1.0/24"},
		}},
	}.RenderConfig()
	if err != nil {
		t.Fatalf("render wireguard: %v", err)
	}

	for _, want := range []string{
		"[Interface]",
		"Address = 10.10.0.1/24",
		"ListenPort = 51820",
		"[Peer]",
		"Endpoint = jp.example.com:51820",
		"AllowedIPs = 10.10.1.0/24",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("expected wireguard config to contain %q:\n%s", want, rendered)
		}
	}
}

func TestFRRConfigRenderBGP(t *testing.T) {
	rendered, err := FRRConfig{
		Hostname: "hk-core",
		RouterID: "10.255.0.1",
		LocalAS:  65001,
		Networks: []string{
			"10.10.0.0/24",
			"10.20.0.0/24",
		},
		Neighbors: []BGPNeighbor{{
			Address:  "10.255.0.2",
			RemoteAS: 65002,
		}},
	}.Render()
	if err != nil {
		t.Fatalf("render frr: %v", err)
	}

	for _, want := range []string{
		"router bgp 65001",
		"bgp router-id 10.255.0.1",
		"network 10.10.0.0/24",
		"neighbor 10.255.0.2 remote-as 65002",
		"maximum-paths 8",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("expected frr config to contain %q:\n%s", want, rendered)
		}
	}
}

func TestFRRConfigRenderFailoverOptions(t *testing.T) {
	rendered, err := FRRConfig{
		Hostname:        "hk-core",
		RouterID:        "10.255.0.1",
		LocalAS:         65001,
		MaximumPaths:    4,
		GracefulRestart: true,
		Neighbors: []BGPNeighbor{{
			Address:  "10.255.0.2",
			RemoteAS: 65002,
			BFD:      true,
		}},
	}.Render()
	if err != nil {
		t.Fatalf("render frr failover options: %v", err)
	}

	for _, want := range []string{
		"bgp graceful-restart",
		"neighbor 10.255.0.2 remote-as 65002",
		"neighbor 10.255.0.2 bfd",
		"maximum-paths 4",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("expected frr failover config to contain %q:\n%s", want, rendered)
		}
	}
}

func TestWireGuardApplyWritesConfigAndRunsSetconf(t *testing.T) {
	runner := &recordingRunner{}
	writer := newRecordingWriter()

	err := WireGuardNode{
		Name:       "hk-core",
		PrivateKey: "private-key",
		ListenPort: 51820,
		Address:    "10.10.0.1/24",
	}.Apply(context.Background(), "wg-core", "/tmp/wg-core.conf", runner, writer)
	if err != nil {
		t.Fatalf("apply wireguard: %v", err)
	}
	if _, ok := writer.files["/tmp/wg-core.conf"]; !ok {
		t.Fatal("expected wireguard config file")
	}
	if len(runner.commands) != 1 || runner.commands[0].name != "wg" {
		t.Fatalf("expected wg command, got %+v", runner.commands)
	}
}

func TestWireGuardApplyLinuxDeviceCreatesAndConfiguresInterface(t *testing.T) {
	runner := &recordingRunner{}
	writer := newRecordingWriter()

	err := WireGuardNode{
		Name:       "hk-core",
		PrivateKey: "private-key",
		ListenPort: 51820,
		Address:    "10.10.0.1/24",
	}.ApplyLinuxDevice(context.Background(), "wg-core", "/tmp/wg-core.conf", runner, writer)
	if err != nil {
		t.Fatalf("apply wireguard linux device: %v", err)
	}
	if _, ok := writer.files["/tmp/wg-core.conf"]; !ok {
		t.Fatal("expected wireguard config file")
	}
	want := []string{
		"ip link add dev wg-core type wireguard",
		"wg setconf wg-core /tmp/wg-core.conf",
		"ip address replace 10.10.0.1/24 dev wg-core",
		"ip link set up dev wg-core",
	}
	got := commandStrings(runner.commands)
	if len(got) != len(want) {
		t.Fatalf("expected %d commands, got %+v", len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("command %d expected %q, got %q", i, want[i], got[i])
		}
	}
}

func TestWireGuardApplyLinuxDeviceWithRollbackDeletesInterfaceOnFailure(t *testing.T) {
	setconfErr := errors.New("setconf failed")
	runner := &recordingRunner{errors: map[string]error{
		"wg setconf wg-core /tmp/wg-core.conf": setconfErr,
	}}
	writer := newRecordingWriter()

	err := WireGuardNode{
		Name:       "hk-core",
		PrivateKey: "private-key",
		ListenPort: 51820,
		Address:    "10.10.0.1/24",
	}.ApplyLinuxDeviceWithRollback(context.Background(), "wg-core", "/tmp/wg-core.conf", runner, writer)
	if err == nil {
		t.Fatal("expected setconf failure")
	}
	if !strings.Contains(err.Error(), setconfErr.Error()) {
		t.Fatalf("expected setconf error, got %v", err)
	}
	got := commandStrings(runner.commands)
	want := []string{
		"ip link add dev wg-core type wireguard",
		"wg setconf wg-core /tmp/wg-core.conf",
		"ip link delete dev wg-core",
	}
	if len(got) != len(want) {
		t.Fatalf("expected rollback command sequence %+v, got %+v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("command %d expected %q, got %q", i, want[i], got[i])
		}
	}
}

func TestFRRApplyWritesConfigAndRunsVtysh(t *testing.T) {
	runner := &recordingRunner{}
	writer := newRecordingWriter()

	err := FRRConfig{
		Hostname: "hk-core",
		RouterID: "10.255.0.1",
		LocalAS:  65001,
	}.Apply(context.Background(), "/tmp/frr.conf", runner, writer)
	if err != nil {
		t.Fatalf("apply frr: %v", err)
	}
	if _, ok := writer.files["/tmp/frr.conf"]; !ok {
		t.Fatal("expected frr config file")
	}
	if len(runner.commands) != 1 || runner.commands[0].name != "vtysh" {
		t.Fatalf("expected vtysh command, got %+v", runner.commands)
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

func commandStrings(commands []recordedCommand) []string {
	result := make([]string, 0, len(commands))
	for _, command := range commands {
		result = append(result, command.String())
	}
	return result
}
