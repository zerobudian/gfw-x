package rules

import (
	"testing"
)

func mkRule(id string, kind Kind, domain string) *Rule {
	return &Rule{ID: id, Kind: kind, Enabled: true,
		Matchers: []Matcher{{Field: FieldDomain, Value: domain}}}
}

// fakeReplace records every replacement so we can assert on the applied state.
func newTestStore() (*RevisionStore, *RuleRepo) {
	repo := NewRepo()
	store := NewRevisionStore(func(rs []*Rule) { repo.Replace(rs) })
	store.EnableBootRevision(repo, "test")
	return store, repo
}

func TestRevisionApplyCreatesSnapshotAndDiffs(t *testing.T) {
	store, repo := newTestStore()

	r1 := mkRule("r1", KindAllow, "github.com")
	r2 := mkRule("r2", KindBlock, "example.com")
	rev1, err := store.Apply([]*Rule{r1, r2}, "alice", "yaml", "add rules")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if rev1.RuleCount != 2 {
		t.Fatalf("rule count = %d, want 2", rev1.RuleCount)
	}
	// Two added changes (both new vs boot snapshot).
	if len(rev1.Changes) != 2 {
		t.Fatalf("changes = %d, want 2 (got %+v)", len(rev1.Changes), rev1.Changes)
	}
	if len(repo.All()) != 2 {
		t.Fatalf("active repo has %d rules, want 2", len(repo.All()))
	}

	// Second apply modifies one rule and removes another.
	r2b := mkRule("r2", KindBlock, "blocked.example.com")
	rev2, err := store.Apply([]*Rule{r1, r2b}, "bob", "yaml", "tune rule")
	if err != nil {
		t.Fatalf("apply2: %v", err)
	}
	if len(rev2.Changes) != 1 {
		t.Fatalf("apply2 changes = %d, want 1 (got %+v)", len(rev2.Changes), rev2.Changes)
	}
	if rev2.Changes[0].Type != ChangeModified || rev2.Changes[0].RuleID != "r2" {
		t.Fatalf("unexpected change: %+v", rev2.Changes[0])
	}
}

func TestRevisionRollbackRestoresPriorSnapshot(t *testing.T) {
	store, repo := newTestStore()

	r1 := mkRule("r1", KindAllow, "github.com")
	rev1, err := store.Apply([]*Rule{r1}, "alice", "yaml", "stage1")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	r2 := mkRule("r2", KindBlock, "example.com")
	rev2, err := store.Apply([]*Rule{r1, r2}, "alice", "yaml", "stage2")
	if err != nil {
		t.Fatalf("apply2: %v", err)
	}
	if len(repo.All()) != 2 {
		t.Fatalf("expected 2 rules after stage2, got %d", len(repo.All()))
	}

	rolled, err := store.Rollback(rev1.ID, "alice")
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got := repo.All(); len(got) != 1 || got[0].ID != "r1" {
		t.Fatalf("after rollback active set = %d rules (first %v), want just r1", len(got), got[0])
	}
	// Rollback chains from the current head (rev2), not the rollback target.
	if rolled.ParentID != rev2.ID {
		t.Fatalf("rollback parent = %q, want %q (chain from current head)", rolled.ParentID, rev2.ID)
	}
	// Rolling back is itself a mutation (-r2) recorded as a new revision.
	if len(rolled.Changes) != 1 || rolled.Changes[0].Type != ChangeRemoved {
		t.Fatalf("rollback changes = %+v, want single removal of r2", rolled.Changes)
	}
}

func TestRevisionDryRunDoesNotMutate(t *testing.T) {
	store, repo := newTestStore()
	base := mkRule("r1", KindAllow, "github.com")
	store.Apply([]*Rule{base}, "alice", "yaml", "stage1")

	incoming := []*Rule{mkRule("r3", KindBlock, "ads.com")}
	prev, err := store.DryRun(incoming)
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !prev.Valid {
		t.Fatalf("dry-run should be valid, got %+v", prev)
	}
	// Dry-run previews a full set swap: remove r1, add r3.
	added, removed := false, false
	for _, c := range prev.Changes {
		switch {
		case c.Type == ChangeAdded && c.RuleID == "r3":
			added = true
		case c.Type == ChangeRemoved && c.RuleID == "r1":
			removed = true
		}
	}
	if !added || !removed {
		t.Fatalf("dry-run changes = %+v, want add r3 and remove r1", prev.Changes)
	}
	// Live state unchanged.
	if got := repo.All(); len(got) != 1 || got[0].ID != "r1" {
		t.Fatalf("dry-run mutated repo: %d rules", len(got))
	}
	// No new revision recorded.
	if n := len(store.History()); n != 1 { // only stage1 application
		t.Fatalf("history length = %d, want 1", n)
	}
}

func TestRevisionApplyRejectsInvalid(t *testing.T) {
	store, _ := newTestStore()
	bad := &Rule{ID: "x", Kind: Kind("nope"), Enabled: true,
		Matchers: []Matcher{{Field: FieldDomain, Value: "x.com"}}}
	if _, err := store.Apply([]*Rule{bad}, "alice", "yaml", "bad"); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestDiffDetectsAddedModifiedRemoved(t *testing.T) {
	from := []*Rule{mkRule("a", KindAllow, "a.com"), mkRule("c", KindBlock, "c.com")}
	to := []*Rule{mkRule("a", KindBlock, "a.com"), mkRule("b", KindAllow, "b.com")}
	changes := Diff(from, to)

	adds := map[string]bool{}
	mods := map[string]bool{}
	removes := map[string]bool{}
	for _, c := range changes {
		switch c.Type {
		case ChangeAdded:
			adds[c.RuleID] = true
		case ChangeModified:
			mods[c.RuleID] = true
		case ChangeRemoved:
			removes[c.RuleID] = true
		}
	}
	if !adds["b"] || !mods["a"] || !removes["c"] {
		t.Fatalf("diff = %+v, want add b, modify a, remove c", changes)
	}
}
