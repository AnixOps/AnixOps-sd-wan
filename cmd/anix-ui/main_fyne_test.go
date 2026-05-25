//go:build fyne

package main

import (
	"fmt"
	"os"
	"testing"
	"time"

	"anixops-sd-wan/internal/transport"
	"anixops-sd-wan/internal/desktop"
)

func TestBuildSystemTrayMenuIncludesActions(t *testing.T) {
	var opened, quit bool
	var notifiedTitle, notifiedContent string
	var enabled, disabled bool
	menu := buildSystemTrayMenu(
		func() { opened = true },
		func() desktop.SelfCheckResult {
			return desktop.SelfCheckResult{Passed: true, Lines: []string{"identity ok"}}
		},
		func(title, content string) {
			notifiedTitle = title
			notifiedContent = content
		},
		func() error {
			enabled = true
			return nil
		},
		func() error {
			disabled = true
			return nil
		},
		func() { quit = true },
	)

	if menu == nil || len(menu.Items) != 6 {
		t.Fatalf("unexpected tray menu: %+v", menu)
	}
	if menu.Items[0].Label != "Show Window" || menu.Items[1].Label != "Run Self-check" || menu.Items[2].Label != "Enable Start at Login" || menu.Items[3].Label != "Disable Start at Login" || menu.Items[5].Label != "Quit" {
		t.Fatalf("unexpected tray menu labels: %+v", []string{menu.Items[0].Label, menu.Items[1].Label, menu.Items[2].Label, menu.Items[3].Label, menu.Items[5].Label})
	}

	menu.Items[0].Action()
	menu.Items[1].Action()
	menu.Items[2].Action()
	menu.Items[3].Action()
	menu.Items[5].Action()

	if !opened || !quit || !enabled || !disabled {
		t.Fatalf("expected tray callbacks to run, opened=%t quit=%t enabled=%t disabled=%t", opened, quit, enabled, disabled)
	}
	if notifiedTitle != "AnixOps self-check passed" || notifiedContent != "identity ok" {
		t.Fatalf("unexpected notification: %q %q", notifiedTitle, notifiedContent)
	}
}

func TestBuildSystemTrayMenuNotifiesAutostartErrors(t *testing.T) {
	var notifiedTitle, notifiedContent string
	menu := buildSystemTrayMenu(
		nil,
		nil,
		func(title, content string) {
			notifiedTitle = title
			notifiedContent = content
		},
		func() error {
			return fmt.Errorf("enable failed")
		},
		func() error {
			return fmt.Errorf("disable failed")
		},
		nil,
	)

	menu.Items[2].Action()
	if notifiedTitle != "AnixOps autostart failed" || notifiedContent != "enable failed" {
		t.Fatalf("unexpected enable error notification: %q %q", notifiedTitle, notifiedContent)
	}
	menu.Items[3].Action()
	if notifiedTitle != "AnixOps autostart failed" || notifiedContent != "disable failed" {
		t.Fatalf("unexpected disable error notification: %q %q", notifiedTitle, notifiedContent)
	}
}

func TestLoadModelFallsBackWithoutAgent(t *testing.T) {
	model, err := loadModel(nil)
	if err != nil {
		t.Fatalf("load model fallback: %v", err)
	}
	if model.DeviceID != "local-dev" || model.TenantID != "default" {
		t.Fatalf("unexpected fallback model identity: %+v", model)
	}
	if model.ConfigVersion != "dev" || model.Link.Protocol != transport.ProtocolHysteria2 {
		t.Fatalf("unexpected fallback model state: %+v", model)
	}
	if model.UpdatedAt.IsZero() || time.Since(model.UpdatedAt) > time.Minute {
		t.Fatalf("expected recent fallback timestamp, got %s", model.UpdatedAt)
	}
}

func TestNewAgentClientRejectsEmptyURL(t *testing.T) {
	if _, err := newAgentClient(""); err != nil {
		t.Fatalf("expected empty agent url to disable client without error, got %v", err)
	}
}

func TestBuildAutostartOptionsUsesProcessPaths(t *testing.T) {
	opts, err := buildAutostartOptions("/opt/anixops/anix-ui")
	if err != nil {
		t.Fatalf("build autostart options: %v", err)
	}
	if opts.AppName != "AnixOps SD-WAN" || opts.ExecPath != "/opt/anixops/anix-ui" {
		t.Fatalf("unexpected autostart options identity: %+v", opts)
	}
	if opts.HomeDir == "" || opts.ConfigDir == "" {
		t.Fatalf("expected user directories to be populated: %+v", opts)
	}
	if opts.AppData != os.Getenv("APPDATA") {
		t.Fatalf("expected appdata to mirror environment, got %+v", opts)
	}
}
