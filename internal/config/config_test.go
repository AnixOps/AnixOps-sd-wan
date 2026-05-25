package config

import "testing"

func TestDefaultConfigValidates(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should validate: %v", err)
	}
}

func TestConfigRequiresAgentIdentity(t *testing.T) {
	cfg := Default()
	cfg.Agent.DeviceID = ""

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected missing device id to fail validation")
	}
}
