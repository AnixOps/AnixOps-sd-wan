package system

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"sort"
	"strings"
)

type ServicePlatform string

const (
	ServicePlatformLinux   ServicePlatform = "linux"
	ServicePlatformDarwin  ServicePlatform = "darwin"
	ServicePlatformWindows ServicePlatform = "windows"
)

type ServiceSpec struct {
	Name        string            `json:"name"`
	DisplayName string            `json:"display_name,omitempty"`
	Description string            `json:"description,omitempty"`
	ExecPath    string            `json:"exec_path"`
	Args        []string          `json:"args,omitempty"`
	WorkingDir  string            `json:"working_dir,omitempty"`
	User        string            `json:"user,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
}

type ServicePlan struct {
	Platform ServicePlatform      `json:"platform"`
	Files    []ServicePlanFile    `json:"files,omitempty"`
	Commands []ServicePlanCommand `json:"commands,omitempty"`
}

type ServicePlanFile struct {
	Path string      `json:"path"`
	Data string      `json:"data"`
	Perm os.FileMode `json:"perm"`
}

type ServicePlanCommand struct {
	Name string   `json:"name"`
	Args []string `json:"args,omitempty"`
}

func RenderServiceInstallPlan(platform ServicePlatform, spec ServiceSpec) (ServicePlan, error) {
	if err := spec.Validate(); err != nil {
		return ServicePlan{}, err
	}
	switch platform {
	case ServicePlatformLinux:
		return linuxServiceInstallPlan(spec), nil
	case ServicePlatformDarwin:
		return darwinServiceInstallPlan(spec), nil
	case ServicePlatformWindows:
		return windowsServiceInstallPlan(spec), nil
	default:
		return ServicePlan{}, fmt.Errorf("unsupported service platform %q", platform)
	}
}

func (s ServiceSpec) Validate() error {
	name := strings.TrimSpace(s.Name)
	if name == "" {
		return fmt.Errorf("service name is required")
	}
	if !safeServiceName(name) {
		return fmt.Errorf("service name %q is unsafe", s.Name)
	}
	if strings.TrimSpace(s.ExecPath) == "" {
		return fmt.Errorf("service exec path is required")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "display name", value: s.DisplayName},
		{name: "description", value: s.Description},
		{name: "exec path", value: s.ExecPath},
		{name: "working dir", value: s.WorkingDir},
		{name: "user", value: s.User},
	} {
		if unsafeServiceField(field.value) {
			return fmt.Errorf("service %s is unsafe", field.name)
		}
	}
	for _, arg := range s.Args {
		if unsafeServiceField(arg) {
			return fmt.Errorf("service argument is unsafe")
		}
	}
	for key, value := range s.Env {
		if !safeEnvName(key) {
			return fmt.Errorf("service environment variable %q is unsafe", key)
		}
		if unsafeServiceField(value) {
			return fmt.Errorf("service environment variable %q value is unsafe", key)
		}
	}
	return nil
}

func (p ServicePlan) Apply(ctx context.Context, writer Writer, runner Runner) error {
	for _, file := range p.Files {
		if writer == nil {
			return fmt.Errorf("writer is required for service plan files")
		}
		if err := writer.WriteFile(file.Path, []byte(file.Data), file.Perm); err != nil {
			return err
		}
	}
	for _, command := range p.Commands {
		if runner == nil {
			return fmt.Errorf("runner is required for service plan commands")
		}
		if err := runner.Run(ctx, command.Name, command.Args...); err != nil {
			return err
		}
	}
	return nil
}

func linuxServiceInstallPlan(spec ServiceSpec) ServicePlan {
	unitName := spec.Name + ".service"
	return ServicePlan{
		Platform: ServicePlatformLinux,
		Files: []ServicePlanFile{{
			Path: "/etc/systemd/system/" + unitName,
			Data: renderSystemdUnit(spec),
			Perm: 0o644,
		}},
		Commands: []ServicePlanCommand{
			{Name: "systemctl", Args: []string{"daemon-reload"}},
			{Name: "systemctl", Args: []string{"enable", unitName}},
			{Name: "systemctl", Args: []string{"restart", unitName}},
		},
	}
}

func darwinServiceInstallPlan(spec ServiceSpec) ServicePlan {
	plistPath := "/Library/LaunchDaemons/" + spec.Name + ".plist"
	return ServicePlan{
		Platform: ServicePlatformDarwin,
		Files: []ServicePlanFile{{
			Path: plistPath,
			Data: renderLaunchdPlist(spec),
			Perm: 0o644,
		}},
		Commands: []ServicePlanCommand{
			{Name: "launchctl", Args: []string{"bootstrap", "system", plistPath}},
			{Name: "launchctl", Args: []string{"kickstart", "-k", "system/" + spec.Name}},
		},
	}
}

func windowsServiceInstallPlan(spec ServiceSpec) ServicePlan {
	displayName := spec.DisplayName
	if displayName == "" {
		displayName = spec.Name
	}
	binPath := commandLine(spec.ExecPath, spec.Args)
	commands := []ServicePlanCommand{{
		Name: "sc.exe",
		Args: []string{"create", spec.Name, "binPath=", binPath, "DisplayName=", displayName, "start=", "auto"},
	}}
	if spec.Description != "" {
		commands = append(commands, ServicePlanCommand{Name: "sc.exe", Args: []string{"description", spec.Name, spec.Description}})
	}
	commands = append(commands,
		ServicePlanCommand{Name: "sc.exe", Args: []string{"failure", spec.Name, "reset=", "60", "actions=", "restart/5000"}},
		ServicePlanCommand{Name: "sc.exe", Args: []string{"start", spec.Name}},
	)
	return ServicePlan{Platform: ServicePlatformWindows, Commands: commands}
}

func renderSystemdUnit(spec ServiceSpec) string {
	description := spec.Description
	if description == "" {
		description = spec.DisplayName
	}
	if description == "" {
		description = spec.Name
	}

	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=" + description + "\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	if spec.WorkingDir != "" {
		b.WriteString("WorkingDirectory=" + spec.WorkingDir + "\n")
	}
	if spec.User != "" {
		b.WriteString("User=" + spec.User + "\n")
	}
	for _, key := range sortedEnvKeys(spec.Env) {
		b.WriteString("Environment=" + quoteSystemdEnv(key+"="+spec.Env[key]) + "\n")
	}
	b.WriteString("ExecStart=" + commandLine(spec.ExecPath, spec.Args) + "\n")
	b.WriteString("Restart=always\n")
	b.WriteString("RestartSec=5s\n\n")
	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String()
}

func renderLaunchdPlist(spec ServiceSpec) string {
	args := append([]string{spec.ExecPath}, spec.Args...)
	var b strings.Builder
	b.WriteString(xml.Header)
	b.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	b.WriteString("<plist version=\"1.0\">\n<dict>\n")
	writePlistKeyString(&b, "Label", spec.Name)
	b.WriteString("<key>ProgramArguments</key>\n<array>\n")
	for _, arg := range args {
		writePlistString(&b, arg)
	}
	b.WriteString("</array>\n")
	if spec.WorkingDir != "" {
		writePlistKeyString(&b, "WorkingDirectory", spec.WorkingDir)
	}
	if len(spec.Env) > 0 {
		b.WriteString("<key>EnvironmentVariables</key>\n<dict>\n")
		for _, key := range sortedEnvKeys(spec.Env) {
			writePlistKeyString(&b, key, spec.Env[key])
		}
		b.WriteString("</dict>\n")
	}
	b.WriteString("<key>RunAtLoad</key>\n<true/>\n")
	b.WriteString("<key>KeepAlive</key>\n<true/>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

func writePlistKeyString(b *strings.Builder, key, value string) {
	b.WriteString("<key>")
	b.WriteString(xmlEscape(key))
	b.WriteString("</key>\n")
	writePlistString(b, value)
}

func writePlistString(b *strings.Builder, value string) {
	b.WriteString("<string>")
	b.WriteString(xmlEscape(value))
	b.WriteString("</string>\n")
}

func xmlEscape(value string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(value))
	return b.String()
}

func sortedEnvKeys(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func commandLine(path string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, quoteCommandArg(path))
	for _, arg := range args {
		parts = append(parts, quoteCommandArg(arg))
	}
	return strings.Join(parts, " ")
}

func quoteCommandArg(arg string) string {
	if arg == "" {
		return `""`
	}
	if !strings.ContainsAny(arg, " \t\"\\") {
		return arg
	}
	escaped := strings.ReplaceAll(arg, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

func quoteSystemdEnv(value string) string {
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`
}

func safeServiceName(name string) bool {
	for _, r := range name {
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func unsafeServiceField(value string) bool {
	return strings.ContainsAny(value, "\x00\r\n")
}

func safeEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r == '_' {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}
