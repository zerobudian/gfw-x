package policy

import (
	"net"
	"testing"
	"time"

	"gfw-x/internal/config"
	"gfw-x/internal/rules"
)

// These benchmarks quantify the cost of DecisionTrace on the policy engine.
// Three variants mirror the runtime sampling choices:
//   - NoTrace:    trace sampling disabled → fast path allocates nothing.
//   - Sampled:    TraceEnabled(sampleRate) gate — most calls skip the trace.
//   - FullTrace:  every decision builds a DecisionTrace object.
//
// run with: go test -bench=BenchmarkTrace -benchmem ./internal/policy/

func benchEngine(b *testing.B) *Engine {
	b.Helper()
	repo := rules.NewRepo()
	repo.Replace([]*rules.Rule{
		{ID: "allow-github", Name: "allow github", Kind: rules.KindAllow, Enabled: true, Matchers: []rules.Matcher{{Field: rules.FieldDomain, Value: "github.com"}}},
		{ID: "block-evil", Name: "block evil", Kind: rules.KindBlock, Enabled: true, Matchers: []rules.Matcher{{Field: rules.FieldDomainSfx, Value: "*.evil.example"}}},
	})
	return NewEngine(repo)
}

func benchInput() *Input {
	return &Input{
		Mode:       config.ModeBlock,
		Attributes: &rules.Attributes{Domain: "foo.evil.example", SNI: "foo.evil.example", DstIP: net.ParseIP("10.0.0.1"), DstPort: 443, Proto: "tcp"},
		Detection:  &DetectionReport{Protocol: "wireguard", Confidence: 0.9, AutoApply: false, Action: "observe"},
	}
}

func BenchmarkTraceNoTrace(b *testing.B) {
	e := benchEngine(b)
	in := benchInput()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e.DecideWithTrace(in, PathFast, nil)
	}
}

func BenchmarkTraceSampled(b *testing.B) {
	e := benchEngine(b)
	in := benchInput()
	b.ReportAllocs()
	// 10% sampling: only a fraction of calls allocate a trace.
	for i := 0; i < b.N; i++ {
		var tr *DecisionTrace
		if TraceEnabled(0.10) {
			tr = NewDecisionTrace()
		}
		e.DecideWithTrace(in, PathFast, tr)
	}
}

func BenchmarkTraceFull(b *testing.B) {
	e := benchEngine(b)
	in := benchInput()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tr := NewDecisionTrace()
		e.DecideWithTrace(in, PathFast, tr)
	}
}

// BenchmarkTraceFullLatency measures the wall-clock overhead of a full trace by
// timing a big batch and dividing — clearer than per-op timer in presence of
// preallocated structs.
func BenchmarkTraceFullLatency(b *testing.B) {
	e := benchEngine(b)
	in := benchInput()
	const batch = 1000
	tr := NewDecisionTrace()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		for j := 0; j < batch; j++ {
			e.DecideWithTrace(in, PathFast, tr)
		}
	}
	_ = start
}
