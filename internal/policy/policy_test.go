package policy

import (
	"net"
	"testing"

	"gfw-x/internal/config"
	"gfw-x/internal/rules"
)

func BaseRepo(t *testing.T) *rules.RuleRepo {
	t.Helper()
	repo := rules.NewRepo()
	repo.Replace([]*rules.Rule{
		{ID: "allow-github", Kind: rules.KindAllow, Enabled: true, Matchers: []rules.Matcher{{Field: rules.FieldDomain, Value: "github.com"}}},
		{ID: "block-blocks", Kind: rules.KindBlock, Enabled: true, Matchers: []rules.Matcher{{Field: rules.FieldDomainSfx, Value: "*.evil.example"}}},
	})
	return repo
}

func TestBypassModeNeverBlocks(t *testing.T) {
	e := NewEngine(BaseRepo(t))
	fd := e.Decide(&Input{Mode: config.ModeBypass, Attributes: &rules.Attributes{Domain: "foo.evil.example"}})
	if fd.Action != "observe" {
		t.Fatalf("bypass mode must observe, got %q", fd.Action)
	}
}

func TestBlockModeEnforcesRules(t *testing.T) {
	e := NewEngine(BaseRepo(t))
	fd := e.Decide(&Input{Mode: config.ModeBlock, Attributes: &rules.Attributes{Domain: "foo.evil.example", DstIP: net.ParseIP("10.0.0.1"), DstPort: 443, Proto: "tcp"}})
	if fd.Action != "block" {
		t.Fatalf("expected block, got %q", fd.Action)
	}
	// explicit allow wins
	fd = e.Decide(&Input{Mode: config.ModeBlock, Attributes: &rules.Attributes{Domain: "github.com", DstIP: net.ParseIP("10.0.0.1"), DstPort: 443, Proto: "tcp"}})
	if fd.Action != "allow" {
		t.Fatalf("explicit allow should win, got %q", fd.Action)
	}
}

func TestUnknownDefaultObserve(t *testing.T) {
	e := NewEngine(BaseRepo(t))
	fd := e.Decide(&Input{Mode: config.ModeBlock, Attributes: &rules.Attributes{Domain: "totally-unknown.example"}})
	if fd.Action != "observe" {
		t.Fatalf("unknown traffic should default to observe, got %q", fd.Action)
	}
}

func TestHighConfidenceAutoApply(t *testing.T) {
	e := NewEngine(BaseRepo(t))
	in := &Input{
		Mode: config.ModeBlock,
		Attributes: &rules.Attributes{Domain: "unknown.org", DstIP: net.ParseIP("198.51.100.1"), DstPort: 443, Proto: "tcp"},
		Detection: &DetectionReport{Protocol: "wireguard", Confidence: 0.95, AutoApply: true, Action: "reject"},
	}
	fd := e.Decide(in)
	if fd.Action != "reject" {
		t.Fatalf("high-confidence auto-apply should reject, got %q", fd.Action)
	}
	// low confidence → not applied
	in.Detection.Confidence = 0.3
	in.Detection.AutoApply = false
	fd = e.Decide(in)
	if fd.Action == "reject" {
		t.Fatalf("low confidence must not block, got %q", fd.Action)
	}
}