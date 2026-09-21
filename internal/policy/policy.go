package policy

import (
	"gfw-x/internal/config"
	"gfw-x/internal/rules"
)

// FinalDecision is the resolved disposition for a flow after policy +
// detection + dpi are folded together.
type FinalDecision struct {
	Action      string // allow|block|observe|ratelimit|reject|drop
	Mode        config.Mode
	MatchedRule string
	Category    string
	Confidence  float64
	Detected    string // detection protocol, if any
	// ActionSource states what decided the final action (rule/detector/
	// default/bypass). Path states which pipeline stage produced it.
	ActionSource ActionSource
	Path         TracePath
	// MatchedRules carries the rules that produced the decision so callers can
	// account hits. Nil when the default (no-rule) policy applied.
	MatchedRules []*rules.Rule
}

// Input is everything the policy engine needs to decide a flow.
type Input struct {
	Attributes *rules.Attributes
	Detection  *DetectionReport
	DPICat     string
	Mode       config.Mode
}

// DetectionReport is a minimal view used by policy (decoupled from detect pkg).
type DetectionReport struct {
	Protocol   string
	Confidence float64
	AutoApply  bool
	Action     string // suggested action from detection
}

// Engine folds rules + mode + detection into a final decision.
type Engine struct {
	RuleRepo *rules.RuleRepo
}

// NewEngine builds a policy engine over a rule repo.
func NewEngine(repo *rules.RuleRepo) *Engine { return &Engine{RuleRepo: repo} }

// Decide returns the final action for an input (fast path, no trace).
func (e *Engine) Decide(in *Input) FinalDecision {
	return e.decide(in, nil, PathFast)
}

// DecideWithTrace returns the final action for an input together with a
// structured DecisionTrace explaining the priority chain. Callers gate this
// behind trace sampling / on-demand explain to keep the fast path cheap.
func (e *Engine) DecideWithTrace(in *Input, path TracePath, tr *DecisionTrace) FinalDecision {
	if tr == nil {
		return e.decide(in, nil, path)
	}
	return e.decide(in, tr, path)
}

func (e *Engine) decide(in *Input, tr *DecisionTrace, path TracePath) FinalDecision {
	fd := FinalDecision{Mode: in.Mode, Path: path}

	// Bypass mode: never enforce, only observe/count.
	if in.Mode == config.ModeBypass {
		fd.Action = "observe"
		fd.ActionSource = SourceBypass
		if tr != nil {
			tr.Action, tr.ActionSource = fd.Action, fd.ActionSource
			tr.Path = PathBypass
		}
		return fd
	}

	// High-confidence detection auto-apply overrides only when configured on.
	if in.Detection != nil && in.Detection.AutoApply {
		a := mapDetectAction(in.Detection.Action)
		switch a {
		case "reject", "drop", "ratelimit":
			fd.Action = a
			fd.Confidence = in.Detection.Confidence
			fd.Detected = in.Detection.Protocol
			fd.ActionSource = SourceDetector
			if tr != nil {
				tr.Action, tr.ActionSource = fd.Action, fd.ActionSource
				tr.Detector = in.Detection.Protocol
				tr.DetectorConf = in.Detection.Confidence
			}
			return fd
		}
		// allow/observe suggestions do not override rules.
	}

	// Rule-based decision (bucket-aware for the trace).
	if tr != nil {
		return e.decideBuckets(in, tr, path)
	}
	b := e.RuleRepo.EvalBuckets(in.Attributes)
	if b.Decision == nil {
		// default policy: unknown → observe (do not blindly drop unknown).
		fd.Action = "observe"
		fd.ActionSource = SourceDefault
		if in.Detection != nil {
			fd.Confidence = in.Detection.Confidence
			fd.Detected = in.Detection.Protocol
		}
		return fd
	}
	fd.Action = b.Decision.Action
	fd.MatchedRule = b.Decision.MatchedRule
	fd.Category = b.Decision.Category
	fd.ActionSource = SourceRuleAction
	fd.MatchedRules = matchedFromBuckets(b)
	return fd
}

func (e *Engine) decideBuckets(in *Input, tr *DecisionTrace, path TracePath) FinalDecision {
	fd := FinalDecision{Mode: in.Mode, Path: path}
	tr.Path = path

	b := e.RuleRepo.EvalBuckets(in.Attributes)
	winning := b.Layer()
	for _, r := range b.Allow {
		tr.AddMatched(r, 0)
	}
	for _, r := range b.Block {
		tr.AddMatched(r, 1)
	}
	for _, r := range b.Category {
		tr.AddMatched(r, 2)
	}
	for _, r := range b.Others {
		tr.AddMatched(r, 3)
	}
	// Surface skipped/overridden rules from lower layers when a control rule won.
	if winning != "" {
		for _, o := range allRules(b) {
			if isControl(o) {
				for _, sql := range allRules(b) {
					if ok, _ := o.ConflictsWith(sql); ok {
						tr.AddSkipped(o, sql)
					}
				}
			}
		}
	}

	if b.Decision == nil {
		fd.Action = "observe"
		fd.ActionSource = SourceDefault
		if in.Detection != nil {
			fd.Confidence = in.Detection.Confidence
			fd.Detected = in.Detection.Protocol
		}
		tr.Action, tr.ActionSource = fd.Action, fd.ActionSource
		return fd
	}
	fd.Action = b.Decision.Action
	fd.MatchedRule = b.Decision.MatchedRule
	fd.Category = b.Decision.Category
	fd.ActionSource = SourceRuleAction
	fd.MatchedRules = matchedFromBuckets(b)
	tr.Action, tr.ActionSource = fd.Action, fd.ActionSource
	return fd
}

func matchedFromBuckets(b *rules.Buckets) []*rules.Rule {
	out := make([]*rules.Rule, 0, len(b.Allow)+len(b.Block)+len(b.Category)+len(b.Others))
	out = append(out, b.Allow...)
	out = append(out, b.Block...)
	out = append(out, b.Category...)
	out = append(out, b.Others...)
	return out
}

func allRules(b *rules.Buckets) []*rules.Rule { return matchedFromBuckets(b) }

func isControl(r *rules.Rule) bool { return r.Kind == rules.KindAllow || r.Kind == rules.KindBlock }

func mapDetectAction(a string) string {
	switch a {
	case "drop", "reject", "ratelimit", "allow", "observe":
		return a
	default:
		return "observe"
	}
}

// PriorityOrder documents the evaluation priority (used by validation tooling).
var PriorityOrder = []string{"explicit allow", "explicit block", "category rule", "default policy"}
