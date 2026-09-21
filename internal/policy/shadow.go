package policy

import (
	"sync"
	"sync/atomic"

	"gfw-x/internal/config"
	"gfw-x/internal/rules"
)

// ShadowReport is the hypothetical outcome of running a flow against the shadow
// rule set, without affecting the real traffic verdict.
type ShadowReport struct {
	FlowID          uint64      `json:"flow_id"`
	CurrentAction   string      `json:"current_action"`
	ShadowAction    string      `json:"shadow_action"`
	MatchedRule     string      `json:"matched_rule,omitempty"`
	ShadowRuleID    string      `json:"shadow_rule_id,omitempty"`
	Disagreement    bool        `json:"disagreement"`
	Mode            config.Mode `json:"mode"`
	ShadowRevisions int64       `json:"shadow_revision,omitempty"`
}

// ShadowStats aggregates shadow-mode decisions for rule-validation dashboards.
type ShadowStats struct {
	Evaluations   atomic.Int64
	WouldAllow    atomic.Int64
	WouldBlock    atomic.Int64
	Disagreements atomic.Int64
}

// Shadow is an observe-only policy engine used to validate new rules before
// they are enforced. It runs the same matching chain against a candidate repo
// and reports what the verdict would have been.
type Shadow struct {
	current *Engine // engine over the current (enforced) repo
	mu      sync.RWMutex
	cand    *Engine // engine over the candidate (shadow) repo
	rev     int64
	has     atomic.Bool
	stats   ShadowStats
}

// NewShadow builds a shadow with an empty candidate set.
func NewShadow(current *Engine) *Shadow {
	return &Shadow{
		current: current,
		cand:    NewEngine(rules.NewRepo()),
	}
}

// SetCurrent rebinds the enforced engine reference (called when rules change).
func (s *Shadow) SetCurrent(eng *Engine) {
	s.mu.Lock()
	s.current = eng
	s.mu.Unlock()
}

// SetCandidateRepo swaps the candidate engine + revision.
func (s *Shadow) SetCandidateRepo(repo *rules.RuleRepo, revision int64) {
	s.mu.Lock()
	s.cand = NewEngine(repo)
	s.rev = revision
	s.has.Store(repo != nil)
	s.mu.Unlock()
}

// HasCandidate reports whether a candidate rule set is installed for
// observe-only validation.
func (s *Shadow) HasCandidate() bool { return s.has.Load() }

// CandidateRevision returns the revision id being validated (0 if none).
func (s *Shadow) CandidateRevision() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.has.Load() {
		return 0
	}
	return s.rev
}

// Compare evaluates a flow against both current and shadow sets.
func (s *Shadow) Compare(in *Input) ShadowReport {
	s.mu.RLock()
	cur := s.current.Decide(in)
	s.mu.RUnlock()
	shadow := s.shadowDecide(in)
	s.stats.Evaluations.Add(1)
	rep := ShadowReport{
		FlowID:          traceFlowID(in),
		CurrentAction:   cur.Action,
		ShadowAction:    shadow.shadowAction,
		MatchedRule:     shadow.matchedRule,
		ShadowRuleID:    shadow.shadowRuleID,
		Mode:            in.Mode,
		ShadowRevisions: s.rev,
	}
	rep.Disagreement = cur.Action != shadow.shadowAction
	if rep.Disagreement {
		s.stats.Disagreements.Add(1)
	}
	switch shadow.shadowAction {
	case "allow", "observe":
		s.stats.WouldAllow.Add(1)
	case "block", "reject", "drop", "ratelimit":
		s.stats.WouldBlock.Add(1)
	default:
		s.stats.WouldAllow.Add(1)
	}
	return rep
}

type shadowDec struct {
	shadowAction string
	matchedRule  string
	shadowRuleID string
}

// shadowDecide runs the candidate engine but forces a non-enforcing context so
// bypass semantics never leak shadow decisions.
func (s *Shadow) shadowDecide(in *Input) shadowDec {
	s.mu.RLock()
	cand := s.cand
	s.mu.RUnlock()
	cp := *in
	// Always evaluate the shadow against the real mode, but treat candidate as
	// an opinion (never override). Bypass still reports what rules would say.
	if cp.Mode == config.ModeBypass {
		cp.Mode = config.ModeBlock
	}
	fd := cand.Decide(&cp)
	d := shadowDec{shadowAction: fd.Action, matchedRule: fd.MatchedRule}
	if len(fd.MatchedRules) > 0 {
		d.shadowRuleID = fd.MatchedRules[0].ID
	}
	return d
}

// Stats returns a snapshot of shadow counters.
func (s *Shadow) Stats() map[string]int64 {
	return map[string]int64{
		"evaluations":  s.stats.Evaluations.Load(),
		"would_allow":  s.stats.WouldAllow.Load(),
		"would_block":  s.stats.WouldBlock.Load(),
		"disagreement": s.stats.Disagreements.Load(),
	}
}

func traceFlowID(in *Input) uint64 { return 0 }
