package integration

import (
	"net/http"
	"testing"
	"time"

	"gfw-x/internal/config"
	"gfw-x/internal/gateway"
	"gfw-x/internal/metrics"
)

func newClient() *http.Client { return &http.Client{Timeout: 3 * time.Second} }

// decision holds the counter deltas produced by feeding one flow.
type decision struct {
	block, allow, observe int64
}

// decide feeds a TLS/443 flow on a fresh 5-tuple and returns the counter deltas.
func decide(t *testing.T, gw *gateway.Gateway, m *metrics.Registry, seq int, sni string) decision {
	t.Helper()
	beforeB, beforeA, beforeO := m.C.Blocked.Load(), m.C.Allowed.Load(), m.C.Observed.Load()
	gw.Ingest(&gateway.Traffic{
		SrcIP: "10.0.0.20", DstIP: "93.184.216.34",
		SrcPort: uint16(30000 + seq%20000), DstPort: 443,
		Transport: "tcp", Sample: clientHello(0x0303, sni, true),
		UpBytes: 256, DownBytes: 4096,
	})
	waitFor(t, 3*time.Second, func() bool {
		return m.C.Blocked.Load() != beforeB ||
			m.C.Allowed.Load() != beforeA ||
			m.C.Observed.Load() != beforeO
	}, "decision")
	return decision{m.C.Blocked.Load() - beforeB, m.C.Allowed.Load() - beforeA, m.C.Observed.Load() - beforeO}
}

// TestModeSwitchE2E drives Bypass -> Block -> Custom -> Bypass on ONE gateway
// instance (no restart) and asserts API/web state + runtime mode + policy
// engine + actual data-plane result at every step.
func TestModeSwitchE2E(t *testing.T) {
	gw, m, cleanup := newGateway(t, config.ModeBypass, "BLOCK example.com\n")
	defer cleanup()
	webCfg := newConfig(config.ModeBypass)
	webCfg.Server.Auth.Enabled = false // web/status reads must not require a session here
	base := startAPI(t, gw, webCfg)
	ctl := newClient()

	startUptime := gw.Uptime()
	step := 0

	// 1) Bypass: blocked rule ignored -> observe (allow).
	if gw.Mode() != config.ModeBypass {
		t.Fatalf("initial mode: %v", gw.Mode())
	}
	if got := modeFromStatus(t, ctl, base, ""); got != "bypass" {
		t.Fatalf("web/status mode: got %q want bypass", got)
	}
	if d := decide(t, gw, m, step, "example.com"); d.block != 0 || d.observe != 1 {
		t.Fatalf("bypass: want observe, got %+v", d)
	}
	step++

	// 2) Block: same rule now enforced -> block.
	if err := gw.SetMode(config.ModeBlock); err != nil {
		t.Fatalf("set block: %v", err)
	}
	if got := modeFromStatus(t, ctl, base, ""); got != "block" {
		t.Fatalf("web/status mode: got %q want block", got)
	}
	if d := decide(t, gw, m, step, "example.com"); d.block != 1 {
		t.Fatalf("block: want block, got %+v", d)
	}
	step++

	// 3) Custom: swap repo to ALLOW example.com -> observe/allow, not block.
	if err := gw.SetMode(config.ModeCustom); err != nil {
		t.Fatalf("set custom: %v", err)
	}
	gw.SetActiveRepo(mustRepo(t, "ALLOW example.com\n"))
	if got := modeFromStatus(t, ctl, base, ""); got != "custom" {
		t.Fatalf("web/status mode: got %q want custom", got)
	}
	if d := decide(t, gw, m, step, "example.com"); d.block != 0 {
		t.Fatalf("custom: want allow/observe (not block), got %+v", d)
	}
	step++

	// 4) Bypass again: no enforcement.
	if err := gw.SetMode(config.ModeBypass); err != nil {
		t.Fatalf("set bypass: %v", err)
	}
	if got := modeFromStatus(t, ctl, base, ""); got != "bypass" {
		t.Fatalf("web/status mode: got %q want bypass", got)
	}
	if d := decide(t, gw, m, step, "example.com"); d.block != 0 || d.observe != 1 {
		t.Fatalf("bypass(2): want observe, got %+v", d)
	}

	if gw.Uptime() != startUptime {
		t.Fatal("gateway was unexpectedly restarted during mode switching")
	}
}

// TestModeSwitchInvalidRejected ensures an invalid mode is refused and traffic
// decisions are unchanged afterwards.
func TestModeSwitchInvalidRejected(t *testing.T) {
	gw, m, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
	defer cleanup()
	if err := gw.SetMode(config.Mode("explode")); err == nil {
		t.Fatal("invalid mode must be rejected")
	}
	if gw.Mode() != config.ModeBlock {
		t.Fatalf("mode must remain unchanged, got %v", gw.Mode())
	}
	if d := decide(t, gw, m, 1, "example.com"); d.block != 1 {
		t.Fatalf("decision must be unaffected by rejected mode change, got %+v", d)
	}
}
