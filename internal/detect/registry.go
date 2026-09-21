package detect

import (
	"sync"
	"sync/atomic"
)

// DetectorInfo identifies a detector for observability and registration.
type DetectorInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Result is a single detector's verdict: which protocol it believes the flow is,
// how confident, and why (the evidence). Detectors only *report*; the Engine is
// responsible for aggregating across detectors and suggesting an Action.
type Result struct {
	Protocol   string
	Confidence float64
	Reasons    []string
}

// Detector is the unit of traffic analysis. Detectors are statically registered
// (no .so/plugin loading) but are plugged into the engine through this interface
// so new analyzers needn't touch the data-plane loop.
//
// Detectors are STATELESS: Inspect is a pure function of its inputs. The data
// plane runs many workers over a single engine, so any per-flow state would be
// shared unsafely across goroutines. Analyzers that need flow history must key
// it externally (e.g. the flow table) and pass it in via Features/Sample.
type Detector interface {
	// Info describes the detector.
	Info() DetectorInfo
	// Inspect analyzes one classification input and returns the detector's
	// verdict. It must not retain arguments across calls.
	Inspect(s Sample, f Features) Result
}

// DetectorStats carries per-detector observability counters. Bounded cardinality:
// the key set is the statically registered detector set, never packet/flow data.
// Plain uint64s are updated with atomic ops so the struct can be copied freely
// (no sync/atomic.Uint64 noCopy embedded) for snapshots.
type DetectorStats struct {
	Runs   uint64
	Panics uint64
}

// GetRuns returns the number of inspections for a detector.
func (s DetectorStats) GetRuns() uint64 { return atomic.LoadUint64(&s.Runs) }

// GetPanics returns the number of recovered panics for a detector.
func (s DetectorStats) GetPanics() uint64 { return atomic.LoadUint64(&s.Panics) }

// Registry is a thread-safe, statically-populated set of detectors with
// per-detector run/panic accounting.
type Registry struct {
	mu        sync.RWMutex
	detectors []Detector
	stats     map[string]*DetectorStats
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{stats: map[string]*DetectorStats{}}
}

// Register adds a detector, replacing any existing entry of the same name.
func (r *Registry) Register(d Detector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.stats[d.Info().Name]; !ok {
		r.stats[d.Info().Name] = &DetectorStats{}
	}
	for i, x := range r.detectors {
		if x.Info().Name == d.Info().Name {
			r.detectors[i] = d
			return
		}
	}
	r.detectors = append(r.detectors, d)
}

// Detectors returns a snapshot of the registered detectors.
func (r *Registry) Detectors() []Detector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Detector, len(r.detectors))
	copy(out, r.detectors)
	return out
}

// StatsFor returns the per-detector stats, creating an entry if absent.
func (r *Registry) StatsFor(name string) *DetectorStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	st, ok := r.stats[name]
	if !ok {
		st = &DetectorStats{}
		r.stats[name] = st
	}
	return st
}

// StatsSnapshot returns a copy of all per-detector counters keyed by name.
func (r *Registry) StatsSnapshot() map[string]DetectorStats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]DetectorStats, len(r.stats))
	for k, v := range r.stats {
		out[k] = DetectorStats{
			Runs:   atomic.LoadUint64(&v.Runs),
			Panics: atomic.LoadUint64(&v.Panics),
		}
	}
	return out
}

// SafeInspect runs a detector's Inspect under a panic guard so a buggy detector
// can never take down the data plane. It always returns a usable Result and
// records panics + runs on the detector's stats.
func (r *Registry) SafeInspect(d Detector, s Sample, f Features) (res Result) {
	info := d.Info()
	st := r.StatsFor(info.Name)
	atomic.AddUint64(&st.Runs, 1)
	defer func() {
		if p := recover(); p != nil {
			atomic.AddUint64(&st.Panics, 1)
			res = Result{Protocol: "unknown", Confidence: 0, Reasons: []string{"detector panic: " + info.Name}}
		}
	}()
	res = d.Inspect(s, f)
	return res
}
