package system

import (
	"context"
	"strings"
	"testing"
)

func TestRenderLinuxServiceInstallPlan(t *testing.T) {
	plan, err := RenderServiceInstallPlan(ServicePlatformLinux, testServiceSpec())
	if err != nil {
		t.Fatalf("render linux service plan: %v", err)
	}
	if plan.Platform != ServicePlatformLinux {
		t.Fatalf("unexpected platform: %s", plan.Platform)
	}
	if len(plan.Files) != 1 || plan.Files[0].Path != "/etc/systemd/system/anix-agent.service" {
		t.Fatalf("unexpected files: %+v", plan.Files)
	}
	unit := plan.Files[0].Data
	for _, want := range []string{
		"Description=AnixOps Agent",
		"After=network-online.target",
		"Environment=\"ANIXOPS_ENV=test\"",
		"ExecStart=/opt/anixops/anix-agent --control-url https://control.example.com --cache-file /var/lib/anixops/cache.json",
		"Restart=always",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("systemd unit missing %q:\n%s", want, unit)
		}
	}
	if got := commandNames(plan.Commands); strings.Join(got, ",") != "systemctl,systemctl,systemctl" {
		t.Fatalf("unexpected commands: %+v", plan.Commands)
	}
	if strings.Join(plan.Commands[1].Args, " ") != "enable anix-agent.service" {
		t.Fatalf("unexpected enable command: %+v", plan.Commands[1])
	}
}

func TestRenderDarwinServiceInstallPlan(t *testing.T) {
	plan, err := RenderServiceInstallPlan(ServicePlatformDarwin, testServiceSpec())
	if err != nil {
		t.Fatalf("render launchd service plan: %v", err)
	}
	if len(plan.Files) != 1 || plan.Files[0].Path != "/Library/LaunchDaemons/anix-agent.plist" {
		t.Fatalf("unexpected files: %+v", plan.Files)
	}
	plist := plan.Files[0].Data
	for _, want := range []string{
		"<key>Label</key>",
		"<string>anix-agent</string>",
		"<key>ProgramArguments</key>",
		"<string>/opt/anixops/anix-agent</string>",
		"<string>--control-url</string>",
		"<key>KeepAlive</key>",
		"<true/>",
	} {
		if !strings.Contains(plist, want) {
			t.Fatalf("launchd plist missing %q:\n%s", want, plist)
		}
	}
	if strings.Join(plan.Commands[0].Args, " ") != "bootstrap system /Library/LaunchDaemons/anix-agent.plist" {
		t.Fatalf("unexpected bootstrap command: %+v", plan.Commands[0])
	}
}

func TestRenderWindowsServiceInstallPlan(t *testing.T) {
	plan, err := RenderServiceInstallPlan(ServicePlatformWindows, testServiceSpec())
	if err != nil {
		t.Fatalf("render windows service plan: %v", err)
	}
	if len(plan.Files) != 0 {
		t.Fatalf("windows plan should not render files: %+v", plan.Files)
	}
	if len(plan.Commands) != 4 {
		t.Fatalf("unexpected commands: %+v", plan.Commands)
	}
	create := plan.Commands[0]
	if create.Name != "sc.exe" {
		t.Fatalf("unexpected command name: %+v", create)
	}
	got := strings.Join(create.Args, "|")
	for _, want := range []string{
		"create|anix-agent|binPath=|/opt/anixops/anix-agent --control-url https://control.example.com --cache-file /var/lib/anixops/cache.json",
		"DisplayName=|AnixOps Agent|start=|auto",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("windows create args missing %q: %+v", want, create.Args)
		}
	}
}

func TestServicePlanApplyUsesWriterAndRunner(t *testing.T) {
	plan, err := RenderServiceInstallPlan(ServicePlatformLinux, testServiceSpec())
	if err != nil {
		t.Fatalf("render service plan: %v", err)
	}
	writer := NewRecordingWriter()
	runner := &RecordingRunner{}
	if err := plan.Apply(context.Background(), writer, runner); err != nil {
		t.Fatalf("apply service plan: %v", err)
	}
	if _, ok := writer.Files["/etc/systemd/system/anix-agent.service"]; !ok {
		t.Fatalf("expected systemd unit write, got %+v", writer.Files)
	}
	if len(runner.Commands) != 3 || runner.Commands[2].Args[0] != "restart" {
		t.Fatalf("unexpected runner commands: %+v", runner.Commands)
	}
}

func TestServiceSpecValidationRejectsUnsafeName(t *testing.T) {
	spec := testServiceSpec()
	spec.Name = "../anix-agent"
	if _, err := RenderServiceInstallPlan(ServicePlatformLinux, spec); err == nil {
		t.Fatal("expected unsafe service name to be rejected")
	}
}

func TestServiceSpecValidationRejectsUnsafeFields(t *testing.T) {
	spec := testServiceSpec()
	spec.Description = "ok\nExecStart=/bin/false"
	if _, err := RenderServiceInstallPlan(ServicePlatformLinux, spec); err == nil {
		t.Fatal("expected unsafe service description to be rejected")
	}

	spec = testServiceSpec()
	spec.Env = map[string]string{"BAD-NAME": "value"}
	if _, err := RenderServiceInstallPlan(ServicePlatformLinux, spec); err == nil {
		t.Fatal("expected unsafe environment name to be rejected")
	}
}

func testServiceSpec() ServiceSpec {
	return ServiceSpec{
		Name:        "anix-agent",
		DisplayName: "AnixOps Agent",
		Description: "AnixOps Agent",
		ExecPath:    "/opt/anixops/anix-agent",
		Args:        []string{"--control-url", "https://control.example.com", "--cache-file", "/var/lib/anixops/cache.json"},
		WorkingDir:  "/var/lib/anixops",
		Env:         map[string]string{"ANIXOPS_ENV": "test"},
	}
}

func commandNames(commands []ServicePlanCommand) []string {
	names := make([]string, 0, len(commands))
	for _, command := range commands {
		names = append(names, command.Name)
	}
	return names
}
