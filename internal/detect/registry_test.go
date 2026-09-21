package detect

import (
	"testing"
)

// panicDetector always panics to exercise data-plane isolation.
type panicDetector struct {
	info DetectorInfo
}

func (d *panicDetector) Info() DetectorInfo { return DetectorInfo{Name: "panicd", Description: "test"} }
func (d *panicDetector) Inspect(s Sample, f Features) Result {
	panic("boom")
}
func TestRegisterAndAggregate(t *testing.T) {
	e := NewEngine(true, 0.5, false)
	if got := len(e.DetectorCounters()); got < 2 {
		t.Fatalf("expected default detectors registered, got %d", got)
	}
	// Register a custom detector.
	e.Register(&testDetector{info: DetectorInfo{Name: "custom", Description: ""},
		res: Result{Protocol: "custom", Confidence: 0.8, Reasons: []string{"custom evidence"}}})
	if got := e.DetectorCounters()["custom"].GetRuns(); got != 0 {
		t.Fatalf("custom detector pre-run = %d", got)
	}
	d := e.Lookup(Sample{}, &Features{})
	_ = d
	if got := e.DetectorCounters()["custom"].GetRuns(); got != 1 {
		t.Fatalf("custom detector runs = %d, want 1", got)
	}
}

func TestPanicGuardIsolatesDataPlane(t *testing.T) {
	e := NewEngine(true, 0.5, false)
	e.Register(&panicDetector{})

	// A lookup runs and completes normally despite the panicking detector.
	d1 := e.Lookup(Sample{}, &Features{})
	if len(d1.Reasons) == 0 {
		t.Fatal("expected a report from default detectors")
	}
	// The panicking detector's panic was caught and counted.
	if got := e.DetectorCounters()["panicd"].GetPanics(); got < 1 {
		t.Fatalf("panic counter = %d, want >= 1", got)
	}
	// The engine remains usable; each subsequent Lookup also recovers.
	_ = e.Lookup(Sample{}, &Features{})
	_ = e.Lookup(Sample{}, &Features{})
}

func TestDisabledEngine(t *testing.T) {
	e := NewEngine(false, 0.5, false)
	d := e.Lookup(Sample{}, &Features{})
	if d.Protocol != "none" || d.Action != ActionAllow {
		t.Fatalf("disabled engine = %+v", d)
	}
	if e.Detections() != 0 {
		t.Fatalf("disabled engine counted detections")
	}
}

// testDetector is a minimal stateless detector for tests.
type testDetector struct {
	info DetectorInfo
	res  Result
}

func (d *testDetector) Info() DetectorInfo { return d.info }
func (d *testDetector) Inspect(s Sample, f Features) Result {
	return d.res
}
