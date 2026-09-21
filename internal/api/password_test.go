package api

import (
	"strings"
	"testing"

	"gfw-x/internal/config"
)

func TestHashPasswordProducesArgon2PHC(t *testing.T) {
	h := hashPassword("S3cret!")
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("expected argon2id PHC prefix, got %q", h)
	}
	// Two hashes of the same password have different salts.
	if hashPassword("pw") == hashPassword("pw") {
		t.Fatal("salts are not random: identical hashes")
	}
}

func TestVerifyArgon2Roundtrip(t *testing.T) {
	pw := "correct horse battery"
	h := hashPassword(pw)
	upgraded, ok := verifyAndUpgrade(pw, h)
	if !ok {
		t.Fatal("verifyAndUpgrade rejected valid password")
	}
	if upgraded != "" {
		t.Fatal("argon2 hash should not be re-upgraded")
	}
	if _, ok := verifyAndUpgrade("wrong", h); ok {
		t.Fatal("verifyAndUpgrade accepted wrong password")
	}
}

func TestLegacyHashMigration(t *testing.T) {
	// A pre-1.1 static-salt double SHA-256 hash.
	legacy := legacyHash("admin")
	if !strings.HasPrefix(legacy, "e158") {
		t.Fatalf("unexpected legacy hash prefix %q", legacy)
	}
	// Correct password migrates: returns an upgraded Argon2 hash.
	upgraded, ok := verifyAndUpgrade("admin", legacy)
	if !ok {
		t.Fatal("legacy hash rejected correct password")
	}
	if upgraded == "" || !strings.HasPrefix(upgraded, "$argon2id$") {
		t.Fatalf("migration did not produce argon2 hash: %q", upgraded)
	}
	// The upgraded hash verifies the same password.
	if _, ok := verifyAndUpgrade("admin", upgraded); !ok {
		t.Fatal("upgraded argon2 hash rejected its password")
	}
}

func TestAuthPasswordConfiguredAndRateLimit(t *testing.T) {
	a := NewAuth(nilAuthCfg(false))
	if a.PasswordConfigured() {
		t.Fatal("empty config should not be PasswordConfigured")
	}
	a.SetPassword("pw", "admin")
	if !a.PasswordConfigured() {
		t.Fatal("after set, password should be configured")
	}
	if !a.PasswordIsArgon2() {
		t.Fatal("SetPassword should produce argon2 hash")
	}
	if ok, _ := a.verifyPassword("pw"); !ok {
		t.Fatal("verifyPassword rejected correct password after SetPassword")
	}

	// Rate limiting on auth-disabled config is a no-op (returns true).
	if !a.enabled {
		for i := 0; i < loginMax*2; i++ {
			if !a.allowLogin("203.0.113.7") {
				t.Fatal("auth disabled should never rate-limit")
			}
		}
	}
}

func TestAllowLoginRateLimitWhenEnabled(t *testing.T) {
	a := NewAuth(nilAuthCfg(true))
	if !a.allowLogin("203.0.113.9") {
		t.Fatal("first login should be allowed")
	}
	for i := 0; i < loginMax; i++ {
		a.recordFailure("203.0.113.9")
	}
	if a.allowLogin("203.0.113.9") {
		t.Fatal("expected rate limit lockout after repeated failures")
	}
}

func nilAuthCfg(enabled bool) *config.Auth {
	return &config.Auth{Enabled: enabled}
}
