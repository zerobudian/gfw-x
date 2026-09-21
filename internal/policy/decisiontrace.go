package policy

import (
	"time"

	"gfw-x/internal/config"
	"gfw-x/internal/rules"
)

// TracePath identifies the pipeline stage that produced the decision.
type TracePath string

const (
	PathFast          TracePath = "fast"
	PathSlow          TracePath = "slow"
	PathBypass        TracePath = "bypass"
	PathQueueOverflow TracePath = "queue_overflow"
)

// ActionSource explains what decided the final action.
type ActionSource string

const (
	SourceRuleAction ActionSource = "rule"
	SourceDetector   ActionSource = "detector"
	SourceDefault    ActionSource = "default"
	SourceBypass     ActionSource = "bypass"
	SourceOverflow   ActionSource = "overflow"
	SourceShadow     ActionSource = "shadow" // hypothetical, not enforced
)

// MatchedRuleTrace is a single contributing rule in a trace.
type MatchedRuleTrace struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Kind     string `json:"kind"`
	Category string `json:"category,omitempty"`
	Action   string `json:"action"`
	Priority int    `json:"priority"`
	Label    string `json:"label"`
}

// ConflictTrace records a rule that overlapped another but was shadowed by the
// priority order (explicit allow > explicit block > category > default).
type ConflictTrace struct {
	A string `json:"rule_a"`
	B string `json:"rule_b"`
}

// DecisionTrace is the structured, JSON-serializable explanation of "why this
// flow got this action". It answers every level of the priority chain so an
// operator can see which rule stage overrode which.
type DecisionTrace struct {
	FlowID          uint64   `json:"flow_id"`
	SrcIP           string   `json:"src_ip"`
	DstIP           string   `json:"dst_ip"`
	SrcPort         uint16   `json:"src_port"`
	DstPort         uint16   `json:"dst_port"`
	Proto           string   `json:"proto"`
	DNSDomain       string   `json:"dns_domain,omitempty"`
	SNI             string   `json:"sni,omitempty"`
	HTTPHost        string   `json:"http_host,omitempty"`
	DPICategory     string   `json:"dpi_category,omitempty"`
	Detector        string   `json:"detector,omitempty"` // protocol label
	DetectorConf    float64  `json:"detector_confidence,omitempty"`
	DetectorReasons []string `json:"detector_reasons,omitempty"`

	MatchedRules []*MatchedRuleTrace `json:"matched_rules"`
	Skipped      []*ConflictTrace    `json:"skipped_conflicts,omitempty"`

	Path         TracePath    `json:"path"`
	Action       string       `json:"action"`
	ActionSource ActionSource `json:"action_source"`
	Mode         config.Mode  `json:"mode"`
	LatencyNS    int64        `json:"latency_ns"`
	Time         time.Time    `json:"time"`
}

// TraceEnabled reports whether a full trace should be produced for a decision.
// Sampling protects the fast path from always allocating large trace objects.
func TraceEnabled(sampleRate float64) bool {
	if sampleRate <= 0 {
		return false
	}
	if sampleRate >= 1 {
		return true
	}
	// cheap deterministic pseudo-sample: no RNG needed, keeps it allocation-light
	return time.Now().UnixNano()%1_000_000 < int64(sampleRate*1_000_000)
}

// NewDecisionTrace allocates an empty trace with timestamps pre-filled.
func NewDecisionTrace() *DecisionTrace {
	return &DecisionTrace{Time: time.Now(), MatchedRules: []*MatchedRuleTrace{}}
}

// AddMatched appends a contributing rule to the trace.
func (t *DecisionTrace) AddMatched(r *rules.Rule, priority int) {
	t.MatchedRules = append(t.MatchedRules, &MatchedRuleTrace{
		ID: r.ID, Name: r.Name, Kind: string(r.Kind),
		Category: r.Category, Action: string(r.Kind), Priority: priority,
		Label: r.Label(),
	})
}

// AddSkipped records a conflicting pair that was not applied.
func (t *DecisionTrace) AddSkipped(a, b *rules.Rule) {
	idA, idB := a.ID, b.ID
	if idA > idB { // canonical ordering so the pair is stable
		idA, idB = idB, idA
	}
	for _, s := range t.Skipped {
		if s.A == idA && s.B == idB {
			return
		}
	}
	t.Skipped = append(t.Skipped, &ConflictTrace{A: idA, B: idB})
}
