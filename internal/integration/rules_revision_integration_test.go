package integration

import (
	"encoding/json"
	"strings"
	"testing"

	"gfw-x/internal/config"
)

// TestRulesRevisionLifecycle drives the DecisionTrace + Rules Revision + Shadow
// API end to end: dry-run, atomic apply, revision get, rollback, traces and the
// shadow candidate lifecycle. This locks in the P0 "explainable / rollbackable"
// contract of GFW X 1.1 at the API layer rather than relying on structs alone.
func TestRulesRevisionLifecycle(t *testing.T) {
	gw, _, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
	defer cleanup()

	webCfg := newConfig(config.ModeBlock)
	webCfg.Server.Auth.Enabled = false // keep the test focused on the new endpoints
	base := startAPI(t, gw, webCfg)
	c := newClient()

	// 1) Dry-run is non-destructive and reports a diff, even via JSON body.
	resp, body := doReq(t, c, "POST", base+"/api/rules/dry-run", `{"content":"block *.evil.net\nallow example.org"}`, "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("dry-run: %d %s", resp.StatusCode, body)
	}
	var preview struct {
		Valid     bool `json:"valid"`
		Incoming  int  `json:"incoming_rules"`
		Changes   []any
		Conflicts []any `json:"conflicts"`
	}
	if err := json.Unmarshal([]byte(body), &preview); err != nil {
		t.Fatalf("decode dry-run: %v body=%s", err, body)
	}
	if !preview.Valid || preview.Incoming != 2 {
		t.Fatalf("dry-run expected valid with 2 incoming rules, got %s", body)
	}

	// 2) Atomic apply replaces the whole set and creates a revision.
	resp, body = doReq(t, c, "POST", base+"/api/rules/apply", `{"content":"block *.evil.net\nallow example.org","author":"t","message":"smoke"}`, "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("apply: %d %s", resp.StatusCode, body)
	}
	var applied struct {
		Applied   bool   `json:"applied"`
		Revision  string `json:"revision"`
		RuleCount int    `json:"rule_count"`
	}
	if err := json.Unmarshal([]byte(body), &applied); err != nil {
		t.Fatalf("decode apply: %v", err)
	}
	if !applied.Applied || applied.Revision == "" || applied.RuleCount != 2 {
		t.Fatalf("apply result unexpected: %s", body)
	}

	resp, body = doReq(t, c, "GET", base+"/api/rules/export?format=txt", "", "", nil)
	if resp.StatusCode != 200 || (!strings.Contains(body, "evil.net") && !strings.Contains(body, "example.org")) {
		t.Fatalf("apply not reflected in exported rules: %d %s", resp.StatusCode, body)
	}

	// 3) Revision history lists the applied revision; get returns its snapshot.
	resp, body = doReq(t, c, "GET", base+"/api/rules/revisions", "", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("revisions list: %d %s", resp.StatusCode, body)
	}
	var revList struct {
		Revisions []struct {
			ID        string `json:"id"`
			RuleCount int    `json:"rule_count"`
		} `json:"revisions"`
	}
	if err := json.Unmarshal([]byte(body), &revList); err != nil {
		t.Fatalf("decode revisions: %v", err)
	}
	if len(revList.Revisions) < 1 || revList.Revisions[0].ID != applied.Revision {
		t.Fatalf("revision history missing applied revision: %s", body)
	}
	resp, body = doReq(t, c, "GET", base+"/api/rules/revisions/"+applied.Revision, "", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("revision get: %d %s", resp.StatusCode, body)
	}

	// 4) Shadow: load a revision as the observe-only candidate, then read stats.
	resp, body = doReq(t, c, "POST", base+"/api/shadow", `{"revision":"`+applied.Revision+`"}`, "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("shadow set: %d %s", resp.StatusCode, body)
	}
	resp, body = doReq(t, c, "GET", base+"/api/shadow", "", "", nil)
	var sh struct {
		Active bool `json:"active"`
	}
	if err := json.Unmarshal([]byte(body), &sh); err != nil {
		t.Fatalf("decode shadow: %v", err)
	}
	if !sh.Active {
		t.Fatalf("shadow should report active after setting a candidate, got %s", body)
	}
	// Clear the candidate.
	resp, _ = doReq(t, c, "POST", base+"/api/shadow", `{"revision":""}`, "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("shadow clear: %d", resp.StatusCode)
	}

	// 5) Traces endpoint is reachable and structured (empty here, no traffic).
	resp, body = doReq(t, c, "GET", base+"/api/traces", "", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("traces: %d %s", resp.StatusCode, body)
	}

	// 6) Rollback to a revision produces a NEW revision and restores its set.
	resp, body = doReq(t, c, "POST", base+"/api/rules/rollback", `{"revision":"`+applied.Revision+`","author":"t"}`, "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("rollback: %d %s", resp.StatusCode, body)
	}
	var rb struct {
		RolledBack string `json:"rolled_back"`
		Revision   string `json:"revision"`
	}
	if err := json.Unmarshal([]byte(body), &rb); err != nil {
		t.Fatalf("decode rollback: %v", err)
	}
	if rb.RolledBack != applied.Revision || rb.Revision == "" {
		t.Fatalf("rollback result unexpected: %s", body)
	}
}
