package config

import "testing"

func TestParseModes(t *testing.T) {
	for _, m := range []string{"bypass", "block", "custom"} {
		if _, err := ParseMode(m); err != nil {
			t.Errorf("ParseMode(%q) error: %v", m, err)
		}
	}
	if _, err := ParseMode("nope"); err == nil {
		t.Error("expected error for invalid mode")
	}
}

func TestParseYAML(t *testing.T) {
	yml := `
server:
  listen: "127.0.0.1:9000"
  lan_only: true
logging:
  format: jsonl
`
	cfg, err := Parse([]byte(yml), ".yaml")
	if err != nil {
		t.Fatalf("parse yaml: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:9000" {
		t.Fatalf("listen=%q", cfg.Server.Listen)
	}
	if cfg.Server.Auth.Enabled != true {
		t.Fatalf("auth default enabled got %v", cfg.Server.Auth.Enabled)
	}
	if cfg.Default.Mode != ModeBlock {
		t.Fatalf("default mode=%q want block", cfg.Default.Mode)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestParseJSON(t *testing.T) {
	js := `{"defaults":{"mode":"bypass"},"logging":{"format":"csv"}}`
	cfg, err := Parse([]byte(js), ".json")
	if err != nil {
		t.Fatalf("parse json: %v", err)
	}
	if cfg.Default.Mode != ModeBypass || cfg.Logging.Format != "csv" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestValidateRejectsBadLogging(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Logging.Format = "xml"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for bad logging format")
	}
}

func TestValidateRejectsDefaultCredOnRemoteListener(t *testing.T) {
	// Seed the well-known default admin hash to exercise the guard: a
	// non-loopback listener must be rejected while the default hash remains.
	cfg := DefaultConfig()
	cfg.Server.Auth.Enabled = true
	cfg.Server.Auth.PasswordHash = defaultAdminHash
	cfg.Server.Listen = "192.168.1.5:8443" // private LAN (allowed) but non-loopback
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected rejection: default credential on non-loopback listener")
	}
	cfg.Server.Auth.PasswordHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("custom password should allow remote bind, got: %v", err)
	}
}

func TestValidateAllowsDefaultCredOnLoopback(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.Auth.Enabled = true
	cfg.Server.Listen = "127.0.0.1:8443"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("loopback listener with default credential should validate, got: %v", err)
	}
}
