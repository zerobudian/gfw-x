package rules

import (
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"
)

// ChangeType is the kind of a rule-set change in a revision.
type ChangeType string

const (
	ChangeAdded    ChangeType = "added"
	ChangeModified ChangeType = "modified"
	ChangeRemoved  ChangeType = "removed"
)

// Change is a single rule-level change between two rule sets.
type Change struct {
	Type   ChangeType `json:"type" yaml:"type"`
	RuleID string     `json:"rule_id" yaml:"rule_id"`
	// Before is a short summary of the previous state (removed/modified).
	Before string `json:"before,omitempty" yaml:"before,omitempty"`
	// After is a short summary of the new state (added/modified).
	After string `json:"after,omitempty" yaml:"after,omitempty"`
}

// Summary returns a compact, human readable one-liner for the change.
func (c *Change) Summary() string {
	switch c.Type {
	case ChangeAdded:
		return fmt.Sprintf("+ %s", c.After)
	case ChangeRemoved:
		return fmt.Sprintf("- %s", c.Before)
	case ChangeModified:
		return fmt.Sprintf("~ %s -> %s", c.Before, c.After)
	}
	return ""
}

// Revision is an immutable snapshot of a rule set together with change metadata.
// Rules are deep-copied so later mutations can never corrupt history.
type Revision struct {
	ID        string    `json:"id" yaml:"id"`
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	Author    string    `json:"author" yaml:"author"`
	Source    string    `json:"source,omitempty" yaml:"source,omitempty"`
	Message   string    `json:"message,omitempty" yaml:"message,omitempty"`
	ParentID  string    `json:"parent_id,omitempty" yaml:"parent_id,omitempty"`
	Changes   []Change  `json:"changes" yaml:"changes"`
	RuleCount int       `json:"rule_count" yaml:"rule_count"`
	rules     []*Rule   // unexported snapshot
}

// Rules returns a deep copy of the snapshot held by the revision.
func (rv *Revision) Rules() []*Rule { return cloneRules(rv.rules) }

// RuleSnapshotName renders a stable identity line for diff purposes.
func ruleSnapshot(r *Rule) string {
	if r.Name != "" {
		return r.Name
	}
	if len(r.Matchers) > 0 {
		return string(r.Matchers[0].Field) + ":" + r.Matchers[0].Value
	}
	return r.ID
}

// ruleContentEqual compares policy-relevant fields, ignoring runtime stats
// (Hits, LastHit) which are not part of the enforced rule definition.
func ruleContentEqual(a, b *Rule) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.ID != b.ID || a.Name != b.Name || a.Kind != b.Kind ||
		a.Enabled != b.Enabled || a.Category != b.Category ||
		a.Source != b.Source || a.Comment != b.Comment {
		return false
	}
	return reflect.DeepEqual(a.Matchers, b.Matchers)
}

// Diff computes the ordered rule-level differences from `from` to `to`.
// The result is deterministic: added/modified rules by ID, removed rules last.
func Diff(from, to []*Rule) []Change {
	idxTo := map[string]*Rule{}
	idxFrom := map[string]*Rule{}
	for _, r := range to {
		idxTo[r.ID] = r
	}
	for _, r := range from {
		idxFrom[r.ID] = r
	}
	var changes []Change
	// Added + modified (iterate the destination set deterministically).
	ids := make([]string, 0, len(idxTo))
	for id := range idxTo {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		b := idxTo[id]
		a, ok := idxFrom[id]
		if !ok {
			changes = append(changes, Change{Type: ChangeAdded, RuleID: id, After: ruleSnapshot(b)})
			continue
		}
		if !ruleContentEqual(a, b) {
			changes = append(changes, Change{Type: ChangeModified, RuleID: id, Before: ruleSnapshot(a), After: ruleSnapshot(b)})
		}
	}
	// Removed (iterate the source set deterministically).
	rm := make([]string, 0)
	for id := range idxFrom {
		if _, ok := idxTo[id]; !ok {
			rm = append(rm, id)
		}
	}
	sort.Strings(rm)
	for _, id := range rm {
		changes = append(changes, Change{Type: ChangeRemoved, RuleID: id, Before: ruleSnapshot(idxFrom[id])})
	}
	return changes
}

// cloneRules deep-copies a rule slice so history snapshots are immutable.
func cloneRules(rs []*Rule) []*Rule {
	out := make([]*Rule, len(rs))
	for i, r := range rs {
		c := *r
		ms := make([]Matcher, len(r.Matchers))
		copy(ms, r.Matchers)
		c.Matchers = ms
		out[i] = &c
	}
	return out
}

// Preview describes the outcome of a dry-run apply without mutating state.
type Preview struct {
	Valid     bool       `json:"valid" yaml:"valid"`
	Incoming  int        `json:"incoming_rules" yaml:"incoming_rules"`
	Changes   []Change   `json:"changes" yaml:"changes"`
	Conflicts []Conflict `json:"conflicts" yaml:"conflicts"`
	Error     string     `json:"error,omitempty" yaml:"error,omitempty"`
}

// RevisionStore provides atomic, snapshot-based rule versioning over a
// RuleRepo. Every apply produces a fresh immutable revision and the underlying
// repo is updated via a single Replace call (atomic recompile + swap), so a
// partial update can never be observed by the data plane.
type RevisionStore struct {
	mu        sync.RWMutex
	revisions []*Revision
	head      *Revision // latest applied revision, for ParentID chains
	// replace is called to atomically swap the active repo's rule set.
	replace func(rs []*Rule)
}

// NewRevisionStore builds a store that applies to the repo managed by `replace`.
func NewRevisionStore(replace func(rs []*Rule)) *RevisionStore {
	return &RevisionStore{replace: replace}
}

// EnableBootRevision records the pre-existing rule set as revision "0" so
// users can always roll back to the state present at startup. safe to call once.
func (s *RevisionStore) EnableBootRevision(repo *RuleRepo, author string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.revisions) > 0 {
		return
	}
	cur := repo.All()
	rv := newRevision(author, "", "initial state", "", cloneRules(cur))
	rv.ID = "rev-0"
	s.revisions = append(s.revisions, rv)
	s.head = rv
}

func newRevision(author, parent, message, source string, snapshot []*Rule) *Revision {
	return &Revision{
		ID:        NewID("rev"),
		CreatedAt: time.Now().UTC(),
		Author:    author,
		Source:    source,
		Message:   message,
		ParentID:  parent,
		RuleCount: len(snapshot),
		rules:     snapshot,
	}
}

// Apply validates, diffs and atomically applies a new rule set, returning the
// new revision. It is the single entry point for import / edit flows.
func (s *RevisionStore) Apply(next []*Rule, author, source, message string) (*Revision, error) {
	dup := cloneRules(next)
	if _, err := validateSet(dup); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	current := s.headRulesLocked()
	changes := Diff(current, dup)

	// Atomic swap on the live repo. The repo compiles indexes only after all
	// rules are in place, so the data plane only ever sees old or new state.
	s.replace(dup)

	rv := newRevision(author, parentID(s.head), message, source, dup)
	rv.Changes = changes
	s.revisions = append(s.revisions, rv)
	s.head = rv
	return rv, nil
}

// Rollback creates a new revision that restores the snapshot of a previous
// revision. Applying a rollback is itself atomic and appears in history as a
// new revision, preserving a full audit path.
func (s *RevisionStore) Rollback(revisionID, author string) (*Revision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	target := s.findLocked(revisionID)
	if target == nil {
		return nil, fmt.Errorf("revision %q not found", revisionID)
	}
	current := s.headRulesLocked()
	snap := target.Rules() // deep copy
	s.replace(snap)
	rv := newRevision(author, parentID(s.head), "rollback to "+revisionID, "rollback", snap)
	rv.Changes = Diff(current, snap)
	s.revisions = append(s.revisions, rv)
	s.head = rv
	return rv, nil
}

// DryRun validates an incoming set and reports the would-be diff and conflicts
// without touching the live repo.
func (s *RevisionStore) DryRun(next []*Rule) (*Preview, error) {
	dup := cloneRules(next)
	if _, err := validateSet(dup); err != nil {
		return &Preview{Valid: false, Incoming: len(dup), Error: err.Error()}, err
	}
	s.mu.RLock()
	current := s.headRulesLocked()
	s.mu.RUnlock()
	return &Preview{
		Valid:     true,
		Incoming:  len(dup),
		Changes:   Diff(current, dup),
		Conflicts: FindConflicts(dup),
	}, nil
}

// History returns revisions oldest-first (excluding the boot revision).
func (s *RevisionStore) History() []*Revision {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Revision, 0, len(s.revisions))
	for i := len(s.revisions) - 1; i >= 0; i-- {
		rv := s.revisions[i]
		if rv.ID == "rev-0" {
			continue
		}
		out = append(out, rv)
	}
	return out
}

// Get returns a revision by id.
func (s *RevisionStore) Get(id string) (*Revision, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rv := s.findLocked(id)
	if rv == nil {
		return nil, false
	}
	return rv, true
}

func (s *RevisionStore) findLocked(id string) *Revision {
	for _, rv := range s.revisions {
		if rv.ID == id {
			return rv
		}
	}
	return nil
}

// headRulesLocked returns a deep copy of the current head snapshot.
func (s *RevisionStore) headRulesLocked() []*Rule {
	if s.head == nil {
		return nil
	}
	return s.head.Rules()
}

func parentID(rv *Revision) string {
	if rv == nil {
		return ""
	}
	return rv.ID
}
