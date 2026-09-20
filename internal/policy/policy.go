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

// Decide returns the final action for an input.
func (e *Engine) Decide(in *Input) FinalDecision {
	fd := FinalDecision{Mode: in.Mode}

	// Bypass mode: never enforce, only observe/count.
	if in.Mode == config.ModeBypass {
		fd.Action = "observe"
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
			return fd
		}
		// allow/observe suggestions do not override rules.
	}

	// Rule-based decision.
	d, matched := e.RuleRepo.Eval(in.Attributes)
	if d == nil {
		// default policy: unknown → observe (do not blindly drop unknown).
		fd.Action = "observe"
		if in.Detection != nil {
			fd.Confidence = in.Detection.Confidence
			fd.Detected = in.Detection.Protocol
		}
		return fd
	}
	fd.Action = d.Action
	fd.MatchedRule = d.MatchedRule
	fd.Category = d.Category
	fd.MatchedRules = matched

	// In block mode only blocking rules act; custom mode uses same rule set
	// (distinguished by which repo is loaded). Both enforce the rules.
	return fd
}

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