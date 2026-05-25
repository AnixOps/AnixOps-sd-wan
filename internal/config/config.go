package config

import "fmt"

type AgentConfig struct {
	TenantID      string
	DeviceID      string
	ConfigVersion string
}

type ControlConfig struct {
	ListenAddr string
}

type Config struct {
	Agent   AgentConfig
	Control ControlConfig
}

func Default() Config {
	return Config{
		Agent: AgentConfig{
			TenantID:      "default",
			DeviceID:      "local-dev",
			ConfigVersion: "dev",
		},
		Control: ControlConfig{
			ListenAddr: "127.0.0.1:8080",
		},
	}
}

func (c Config) Validate() error {
	if c.Agent.TenantID == "" {
		return fmt.Errorf("agent tenant id is required")
	}
	if c.Agent.DeviceID == "" {
		return fmt.Errorf("agent device id is required")
	}
	if c.Agent.ConfigVersion == "" {
		return fmt.Errorf("agent config version is required")
	}
	if c.Control.ListenAddr == "" {
		return fmt.Errorf("control listen address is required")
	}
	return nil
}
