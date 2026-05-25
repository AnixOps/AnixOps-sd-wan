//go:build fyne

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"anixops-sd-wan/internal/agent"
	"anixops-sd-wan/internal/desktop"
	"anixops-sd-wan/internal/transport"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	fyneDesktop "fyne.io/fyne/v2/driver/desktop"
)

func main() {
	agentURL := flag.String("agent-url", "http://127.0.0.1:18080", "local agent API base URL")
	flag.Parse()

	agentClient, err := newAgentClient(*agentURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "desktop state error: %v\n", err)
		os.Exit(1)
	}
	model, err := loadModel(agentClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "desktop state error: %v\n", err)
		os.Exit(1)
	}
	execPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "desktop state error: %v\n", err)
		os.Exit(1)
	}
	autostartOpts, err := buildAutostartOptions(execPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "desktop state error: %v\n", err)
		os.Exit(1)
	}

	a := app.NewWithID("io.anixops.sdwan")
	w := a.NewWindow("AnixOps SD-WAN")
	w.SetContent(desktop.NewOverviewCanvas(model, agentClient, autostartOpts))
	w.Resize(fyne.NewSize(860, 560))
	configureTray(a, w, model, autostartOpts)
	w.ShowAndRun()
}

func newAgentClient(agentURL string) (*desktop.AgentClient, error) {
	if agentURL == "" {
		return nil, nil
	}
	return desktop.NewAgentClient(agentURL, nil)
}

func loadModel(client *desktop.AgentClient) (desktop.ViewModel, error) {
	if client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
		defer cancel()
		model, err := client.ViewModel(ctx)
		if err == nil {
			return model, nil
		}
		fmt.Fprintf(os.Stderr, "local agent unavailable, using fallback state: %v\n", err)
	}

	return desktop.NewViewModel(agent.Snapshot{
		TenantID:      "default",
		DeviceID:      "local-dev",
		Platform:      "desktop",
		Running:       true,
		ConfigVersion: "dev",
		UpdatedAt:     time.Now().UTC(),
	}, desktop.LinkStatus{
		LinkClass:    transport.LinkPublic,
		Protocol:     transport.ProtocolHysteria2,
		EgressNodeID: "unassigned",
		UDPAvailable: true,
	}, desktop.CertificateStatus{}, []string{"desktop ui started"})
}

func buildAutostartOptions(execPath string) (desktop.AutostartOptions, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return desktop.AutostartOptions{}, err
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return desktop.AutostartOptions{}, err
	}
	return desktop.AutostartOptions{
		AppName:   "AnixOps SD-WAN",
		ExecPath:  execPath,
		Args:      nil,
		HomeDir:   homeDir,
		ConfigDir: configDir,
		AppData:   os.Getenv("APPDATA"),
	}, nil
}

func configureTray(a fyne.App, w fyne.Window, model desktop.ViewModel, autostartOpts desktop.AutostartOptions) {
	desk, ok := a.(fyneDesktop.App)
	if !ok {
		return
	}
	menu := buildSystemTrayMenu(
		func() {
			w.Show()
			w.RequestFocus()
		},
		func() desktop.SelfCheckResult {
			return desktop.RunSelfCheck(model)
		},
		func(title, content string) {
			a.SendNotification(&fyne.Notification{Title: title, Content: content})
		},
		func() error {
			plan, err := desktop.EnableAutostart(autostartOpts)
			if err != nil {
				return err
			}
			a.SendNotification(&fyne.Notification{Title: "AnixOps autostart enabled", Content: plan.Path})
			return nil
		},
		func() error {
			path, err := desktop.DisableAutostart(autostartOpts)
			if err != nil {
				return err
			}
			a.SendNotification(&fyne.Notification{Title: "AnixOps autostart disabled", Content: path})
			return nil
		},
		func() {
			a.Quit()
		},
	)
	desk.SetSystemTrayMenu(menu)
	desk.SetSystemTrayWindow(w)
}

func buildSystemTrayMenu(open func(), runSelfCheck func() desktop.SelfCheckResult, notify func(title, content string), enableAutostart func() error, disableAutostart func() error, quit func()) *fyne.Menu {
	if open == nil {
		open = func() {}
	}
	if runSelfCheck == nil {
		runSelfCheck = func() desktop.SelfCheckResult { return desktop.SelfCheckResult{} }
	}
	if notify == nil {
		notify = func(title, content string) {}
	}
	if enableAutostart == nil {
		enableAutostart = func() error { return nil }
	}
	if disableAutostart == nil {
		disableAutostart = func() error { return nil }
	}
	if quit == nil {
		quit = func() {}
	}

	return fyne.NewMenu("AnixOps SD-WAN",
		fyne.NewMenuItem("Show Window", open),
		fyne.NewMenuItem("Run Self-check", func() {
			check := runSelfCheck()
			title := "AnixOps self-check passed"
			if !check.Passed {
				title = "AnixOps self-check needs attention"
			}
			notify(title, strings.Join(check.Lines, "; "))
		}),
		fyne.NewMenuItem("Enable Start at Login", func() {
			if err := enableAutostart(); err != nil {
				notify("AnixOps autostart failed", err.Error())
			}
		}),
		fyne.NewMenuItem("Disable Start at Login", func() {
			if err := disableAutostart(); err != nil {
				notify("AnixOps autostart failed", err.Error())
			}
		}),
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("Quit", quit),
	)
}
