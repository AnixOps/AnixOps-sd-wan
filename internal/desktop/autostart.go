package desktop

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type AutostartOptions struct {
	AppName   string
	ExecPath  string
	Args      []string
	HomeDir   string
	ConfigDir string
	AppData   string
}

type AutostartPlan struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

func EnableAutostart(opts AutostartOptions) (AutostartPlan, error) {
	plan, err := BuildAutostartPlan(runtime.GOOS, opts)
	if err != nil {
		return AutostartPlan{}, err
	}
	if err := os.MkdirAll(filepath.Dir(plan.Path), 0o755); err != nil {
		return AutostartPlan{}, fmt.Errorf("create autostart directory: %w", err)
	}
	if err := os.WriteFile(plan.Path, []byte(plan.Content), 0o644); err != nil {
		return AutostartPlan{}, fmt.Errorf("write autostart file: %w", err)
	}
	return plan, nil
}

func DisableAutostart(opts AutostartOptions) (string, error) {
	plan, err := BuildAutostartPlan(runtime.GOOS, opts)
	if err != nil {
		return "", err
	}
	if err := os.Remove(plan.Path); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("remove autostart file: %w", err)
	}
	return plan.Path, nil
}

func AutostartState(opts AutostartOptions) (bool, string, error) {
	plan, err := BuildAutostartPlan(runtime.GOOS, opts)
	if err != nil {
		return false, "", err
	}
	_, statErr := os.Stat(plan.Path)
	if statErr == nil {
		return true, plan.Path, nil
	}
	if os.IsNotExist(statErr) {
		return false, plan.Path, nil
	}
	return false, plan.Path, fmt.Errorf("check autostart file: %w", statErr)
}

func BuildAutostartPlan(platform string, opts AutostartOptions) (AutostartPlan, error) {
	if strings.TrimSpace(opts.AppName) == "" {
		return AutostartPlan{}, fmt.Errorf("app name is required")
	}
	if strings.TrimSpace(opts.ExecPath) == "" {
		return AutostartPlan{}, fmt.Errorf("exec path is required")
	}
	args := append([]string(nil), opts.Args...)
	switch platform {
	case "linux":
		configDir := strings.TrimSpace(opts.ConfigDir)
		if configDir == "" {
			home := strings.TrimSpace(opts.HomeDir)
			if home == "" {
				return AutostartPlan{}, fmt.Errorf("config dir is required")
			}
			configDir = filepath.Join(home, ".config")
		}
		path := filepath.Join(configDir, "autostart", "anix-ui.desktop")
		content := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=%s
Exec=%s%s
X-GNOME-Autostart-enabled=true
`, opts.AppName, quoteShellPath(opts.ExecPath), renderShellArgs(args))
		return AutostartPlan{Path: path, Content: content}, nil
	case "darwin":
		home := strings.TrimSpace(opts.HomeDir)
		if home == "" {
			return AutostartPlan{}, fmt.Errorf("home dir is required")
		}
		path := filepath.Join(home, "Library", "LaunchAgents", "io.anixops.sdwan.ui.plist")
		content := buildLaunchAgentPlist(opts.AppName, opts.ExecPath, args)
		return AutostartPlan{Path: path, Content: content}, nil
	case "windows":
		appData := strings.TrimSpace(opts.AppData)
		if appData == "" {
			configDir := strings.TrimSpace(opts.ConfigDir)
			if configDir == "" {
				return AutostartPlan{}, fmt.Errorf("app data dir is required")
			}
			appData = configDir
		}
		path := windowsPathJoin(appData, "Microsoft", "Windows", "Start Menu", "Programs", "Startup", "AnixOps SD-WAN.bat")
		content := "@echo off\r\nstart \"\" " + quoteWindowsArg(opts.ExecPath) + renderWindowsArgs(args) + "\r\n"
		return AutostartPlan{Path: path, Content: content}, nil
	default:
		return AutostartPlan{}, fmt.Errorf("unsupported platform %q", platform)
	}
}

func buildLaunchAgentPlist(appName, execPath string, args []string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>io.anixops.sdwan.ui</string>
<key>ProgramArguments</key>
<array>
<string>`)
	b.WriteString(xmlEscape(execPath))
	b.WriteString(`</string>
`)
	for _, arg := range args {
		b.WriteString("<string>")
		b.WriteString(xmlEscape(arg))
		b.WriteString("</string>\n")
	}
	b.WriteString(`</array>
<key>RunAtLoad</key>
<true/>
<key>KeepAlive</key>
<false/>
</dict>
</plist>
`)
	return b.String()
}

func renderShellArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	var b strings.Builder
	for _, arg := range args {
		b.WriteByte(' ')
		b.WriteString(quoteShellPath(arg))
	}
	return b.String()
}

func renderWindowsArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	var b strings.Builder
	for _, arg := range args {
		b.WriteByte(' ')
		b.WriteString(quoteWindowsArg(arg))
	}
	return b.String()
}

func quoteShellPath(value string) string {
	if strings.ContainsAny(value, " \t\n\"'") {
		return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
	}
	return value
}

func quoteWindowsArg(value string) string {
	return "\"" + strings.ReplaceAll(value, "\"", "\"\"") + "\""
}

func xmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&apos;")
	return replacer.Replace(value)
}

func windowsPathJoin(parts ...string) string {
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		part = strings.TrimRight(part, `\/`)
		if part != "" {
			cleaned = append(cleaned, part)
		}
	}
	if len(cleaned) == 0 {
		return ""
	}
	return strings.Join(cleaned, `\`)
}
