package desktop

import (
	"fmt"
	"strings"

	"anixops-sd-wan/internal/transport"
)

type SelfCheckResult struct {
	Passed bool     `json:"passed"`
	Lines  []string `json:"lines"`
}

func RunSelfCheck(model ViewModel) SelfCheckResult {
	var lines []string
	passed := true

	if model.DeviceID == "" || model.TenantID == "" {
		lines = append(lines, "identity missing")
		passed = false
	} else {
		lines = append(lines, "identity ok")
	}
	if !model.Running {
		lines = append(lines, "agent stopped")
		passed = false
	} else {
		lines = append(lines, "agent running")
	}
	if model.ConfigVersion == "" {
		lines = append(lines, "config version missing")
		passed = false
	} else {
		lines = append(lines, "config version: "+model.ConfigVersion)
	}
	if !transport.KnownProtocol(model.Link.Protocol) {
		lines = append(lines, "protocol missing")
		passed = false
	} else {
		lines = append(lines, fmt.Sprintf("protocol: %s", model.Link.Protocol))
	}
	if model.Link.UDPAvailable {
		lines = append(lines, "udp available")
	} else {
		lines = append(lines, "udp unavailable")
		passed = false
	}
	if len(model.Alerts) == 0 {
		lines = append(lines, "alerts clear")
	} else {
		lines = append(lines, "alerts: "+strings.Join(model.Alerts, ", "))
		passed = false
	}

	return SelfCheckResult{
		Passed: passed,
		Lines:  lines,
	}
}
