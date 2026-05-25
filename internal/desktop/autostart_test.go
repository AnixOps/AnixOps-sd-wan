package desktop

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildAutostartPlanLinux(t *testing.T) {
	plan, err := BuildAutostartPlan("linux", AutostartOptions{
		AppName:   "AnixOps SD-WAN",
		ExecPath:  "/opt/anixops/anix-ui",
		ConfigDir: "/home/test/.config",
	})
	if err != nil {
		t.Fatalf("build linux autostart plan: %v", err)
	}
	if plan.Path != "/home/test/.config/autostart/anix-ui.desktop" {
		t.Fatalf("unexpected linux path: %s", plan.Path)
	}
	for _, want := range []string{
		"[Desktop Entry]",
		"Name=AnixOps SD-WAN",
		"Exec=/opt/anixops/anix-ui",
		"X-GNOME-Autostart-enabled=true",
	} {
		if !strings.Contains(plan.Content, want) {
			t.Fatalf("linux plan missing %q:\n%s", want, plan.Content)
		}
	}
}

func TestBuildAutostartPlanDarwin(t *testing.T) {
	plan, err := BuildAutostartPlan("darwin", AutostartOptions{
		AppName:  "AnixOps SD-WAN",
		ExecPath: "/Applications/AnixOps SD-WAN.app/Contents/MacOS/anix-ui",
		HomeDir:  "/Users/test",
	})
	if err != nil {
		t.Fatalf("build darwin autostart plan: %v", err)
	}
	if plan.Path != "/Users/test/Library/LaunchAgents/io.anixops.sdwan.ui.plist" {
		t.Fatalf("unexpected darwin path: %s", plan.Path)
	}
	for _, want := range []string{
		"<key>RunAtLoad</key>",
		"<string>/Applications/AnixOps SD-WAN.app/Contents/MacOS/anix-ui</string>",
		"<string>io.anixops.sdwan.ui</string>",
	} {
		if !strings.Contains(plan.Content, want) {
			t.Fatalf("darwin plan missing %q:\n%s", want, plan.Content)
		}
	}
}

func TestBuildAutostartPlanWindows(t *testing.T) {
	plan, err := BuildAutostartPlan("windows", AutostartOptions{
		AppName:  "AnixOps SD-WAN",
		ExecPath: `C:\AnixOps\anix-ui.exe`,
		AppData:  `C:\Users\test\AppData\Roaming`,
	})
	if err != nil {
		t.Fatalf("build windows autostart plan: %v", err)
	}
	if plan.Path != `C:\Users\test\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\AnixOps SD-WAN.bat` {
		t.Fatalf("unexpected windows path: %s", plan.Path)
	}
	for _, want := range []string{
		"@echo off",
		`start "" "C:\AnixOps\anix-ui.exe"`,
	} {
		if !strings.Contains(plan.Content, want) {
			t.Fatalf("windows plan missing %q:\n%s", want, plan.Content)
		}
	}
}

func TestAutostartStateDetectsEnabledFile(t *testing.T) {
	opts := AutostartOptions{
		AppName:   "AnixOps SD-WAN",
		ExecPath:  "/opt/anixops/anix-ui",
		ConfigDir: filepath.Join(t.TempDir(), ".config"),
	}
	plan, err := BuildAutostartPlan("linux", opts)
	if err != nil {
		t.Fatalf("build autostart plan: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(plan.Path), 0o755); err != nil {
		t.Fatalf("mkdir autostart dir: %v", err)
	}
	if err := os.WriteFile(plan.Path, []byte(plan.Content), 0o644); err != nil {
		t.Fatalf("write autostart file: %v", err)
	}
	enabled, path, err := AutostartState(opts)
	if err != nil {
		t.Fatalf("autostart state: %v", err)
	}
	if !enabled || path != plan.Path {
		t.Fatalf("unexpected autostart state: enabled=%t path=%s want=%s", enabled, path, plan.Path)
	}
}

func TestBuildAutostartPlanValidatesInputs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		platform string
		opts     AutostartOptions
		wantErr  string
	}{
		{
			name:     "missing app name",
			platform: "linux",
			opts: AutostartOptions{
				ExecPath:  "/opt/anixops/anix-ui",
				ConfigDir: "/home/test/.config",
			},
			wantErr: "app name is required",
		},
		{
			name:     "missing exec path",
			platform: "darwin",
			opts: AutostartOptions{
				AppName: "AnixOps SD-WAN",
				HomeDir: "/Users/test",
			},
			wantErr: "exec path is required",
		},
		{
			name:     "unsupported platform",
			platform: "plan9",
			opts: AutostartOptions{
				AppName:  "AnixOps SD-WAN",
				ExecPath: "/opt/anixops/anix-ui",
			},
			wantErr: "unsupported platform",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := BuildAutostartPlan(tc.platform, tc.opts); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestBuildAutostartPlanEscapesArguments(t *testing.T) {
	linuxPlan, err := BuildAutostartPlan("linux", AutostartOptions{
		AppName:  "AnixOps SD-WAN",
		ExecPath: "/opt/anixops/anix ui",
		Args:     []string{"--profile", "two words", "quote's"},
		ConfigDir: "/home/test/.config",
	})
	if err != nil {
		t.Fatalf("build linux autostart plan: %v", err)
	}
	for _, want := range []string{
		"Exec='/opt/anixops/anix ui' --profile 'two words' 'quote'\\''s'",
	} {
		if !strings.Contains(linuxPlan.Content, want) {
			t.Fatalf("linux plan missing escaped args %q:\n%s", want, linuxPlan.Content)
		}
	}

	darwinPlan, err := BuildAutostartPlan("darwin", AutostartOptions{
		AppName:  "AnixOps SD-WAN",
		ExecPath: "/Applications/AnixOps SD-WAN.app/Contents/MacOS/anix-ui",
		Args:     []string{"--profile", "two & words", `alpha"beta`},
		HomeDir:  "/Users/test",
	})
	if err != nil {
		t.Fatalf("build darwin autostart plan: %v", err)
	}
	for _, want := range []string{
		"<string>--profile</string>",
		"<string>two &amp; words</string>",
		"<string>alpha&quot;beta</string>",
	} {
		if !strings.Contains(darwinPlan.Content, want) {
			t.Fatalf("darwin plan missing escaped args %q:\n%s", want, darwinPlan.Content)
		}
	}

	windowsPlan, err := BuildAutostartPlan("windows", AutostartOptions{
		AppName:  "AnixOps SD-WAN",
		ExecPath: `C:\AnixOps\anix-ui.exe`,
		Args:     []string{"--profile", `two words`, `alpha"beta`},
		AppData:  `C:\Users\test\AppData\Roaming`,
	})
	if err != nil {
		t.Fatalf("build windows autostart plan: %v", err)
	}
	for _, want := range []string{
		`start "" "C:\AnixOps\anix-ui.exe" "--profile" "two words" "alpha""beta"`,
	} {
		if !strings.Contains(windowsPlan.Content, want) {
			t.Fatalf("windows plan missing escaped args %q:\n%s", want, windowsPlan.Content)
		}
	}
}

func TestEnableAndDisableAutostartRoundTrip(t *testing.T) {
	opts := AutostartOptions{
		AppName:   "AnixOps SD-WAN",
		ExecPath:  "/opt/anixops/anix-ui",
		ConfigDir: filepath.Join(t.TempDir(), ".config"),
	}

	plan, err := EnableAutostart(opts)
	if err != nil {
		t.Fatalf("enable autostart: %v", err)
	}
	if _, err := os.Stat(plan.Path); err != nil {
		t.Fatalf("expected autostart file to exist: %v", err)
	}
	enabled, path, err := AutostartState(opts)
	if err != nil {
		t.Fatalf("autostart state after enable: %v", err)
	}
	if !enabled || path != plan.Path {
		t.Fatalf("unexpected enabled state: enabled=%t path=%s want=%s", enabled, path, plan.Path)
	}

	removedPath, err := DisableAutostart(opts)
	if err != nil {
		t.Fatalf("disable autostart: %v", err)
	}
	if removedPath != plan.Path {
		t.Fatalf("unexpected disabled path: %s", removedPath)
	}
	if _, err := os.Stat(plan.Path); !os.IsNotExist(err) {
		t.Fatalf("expected autostart file to be removed, got err=%v", err)
	}
	enabled, path, err = AutostartState(opts)
	if err != nil {
		t.Fatalf("autostart state after disable: %v", err)
	}
	if enabled || path != plan.Path {
		t.Fatalf("unexpected disabled state: enabled=%t path=%s want=%s", enabled, path, plan.Path)
	}
}
