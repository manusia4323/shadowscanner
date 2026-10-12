package config

import (
	"testing"
)

func TestConfigLoadAndValidate(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if cfg.Port < 1024 || cfg.Port > 65535 {
		t.Errorf("unexpected port: %d", cfg.Port)
	}
	if cfg.RetentionHours < 1 || cfg.RetentionHours > 720 {
		t.Errorf("unexpected retention: %d", cfg.RetentionHours)
	}
}
