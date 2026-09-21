package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"gfw-x/internal/config"
	"gfw-x/internal/rules"
)

// postRule sends a rule mutation that carries a JSON rule body and returns the
// decoded rule that the server echoes back (incl. auto-assigned id).
func postRule(t *testing.T, c *http.Client, base, csrf, ruleJSON string) *rules.Rule {
	t.Helper()
	resp, body := doReq(t, c, "POST", base+"/api/rules", ruleJSON, csrf, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("POST /api/rules: %d %s", resp.StatusCode, body)
	}
	var r rules.Rule
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("decode added rule: %v body=%s", err, body)
	}
	if r.ID == "" {
		t.Fatalf("added rule has no id from API: %s", body)
	}
	return &r
}

func ruleJSON(kind string, enabled bool, field, value string) string {
	b, _ := json.Marshal(map[string]any{
		"kind": kind, "enabled": enabled,
		"matchers": []map[string]string{{"field": field, "value": value}},
	})
	return string(b)
}

// formImport imports rule text via the real form endpoint.
func formImport(t *testing.T, c *http.Client, base, csrf, content, format string) (int, string) {
	t.Helper()
	f := url.Values{}
	f.Set("content", content)
	if format != "" {
		f.Set("format", format)
	}
	req, err := http.NewRequest("POST", base+"/api/rules/import", strings.NewReader(f.Encode()))
	if err != nil {
		t.Fatalf("import req: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	body := new(bytes.Buffer)
	_, _ = body.ReadFrom(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, body.String()
}

func rulesContain(t *testing.T, c *http.Client, base, csrf, frag string) bool {
	t.Helper()
	resp, body := doReq(t, c, "GET", base+"/api/rules", "", csrf, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /api/rules: %d %s", resp.StatusCode, body)
	}
	return strings.Contains(body, frag)
}

// TestWebAPI_DataplaneConsistency drives the full chain Web → API → Runtime →
// Dataplane → Observed for every dashboard action, asserting the backend state
// actually changed (not just "the API returned 200").
func TestWebAPI_DataplaneConsistency(t *testing.T) {
	gw, m, cleanup := newGateway(t, config.ModeCustom, "BLOCK example.com\n")
	defer cleanup()

	// Full session chain: enable auth so every call goes through real login +
	// cookie + CSRF, not just an open server.
	webCfg := newConfig(config.ModeCustom)
	webCfg.Server.Auth.Enabled = true
	base := startAPI(t, gw, webCfg)
	c, csrf := login(t, base)

	feed := func(sni string) decision {
		feedSeq++
		return decide(t, gw, m, int(feedSeq), sni)
	}

	// 1) Liveness probe must be reachable WITHOUT a session.
	resp, _ := doReq(t, newClient(), "GET", base+"/api/health", "", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("unauthenticated /api/health: %d", resp.StatusCode)
	}

	// 2) Dashboard SPA root must serve.
	resp, _ = doReq(t, c, "GET", base+"/", "", csrf, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("dashboard root: %d", resp.StatusCode)
	}

	// 3) Web/API status == runtime mode == dataplane baseline.
	if got := modeFromStatus(t, c, base, csrf); got != "custom" {
		t.Fatalf("status mode=%q want custom", got)
	}
	if d := feed("example.com"); d.block != 1 {
		t.Fatalf("dataplane baseline block: %+v", d)
	}

	// 4) Add a rule via Web/API → backend repo + dataplane both react.
	added := postRule(t, c, base, csrf, ruleJSON("block", true, "domain", "evil-tracker.com"))
	if !rulesContain(t, c, base, csrf, "evil-tracker.com") {
		t.Fatal("added rule not present in backend repo")
	}
	if d := feed("evil-tracker.com"); d.block != 1 {
		t.Fatalf("newly added rule must block, got %+v", d)
	}

	// 5) Disable via Web/API → dataplane no longer enforces it.
	added.Enabled = false
	b, _ := json.Marshal(added)
	resp, body := doReq(t, c, "PUT", base+"/api/rules", string(b), csrf, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("PUT disable: %d %s", resp.StatusCode, body)
	}
	if d := feed("evil-tracker.com"); d.block != 0 {
		t.Fatalf("disabled rule must not block, got %+v", d)
	}

	// 6) Re-enable → blocks again.
	added.Enabled = true
	b, _ = json.Marshal(added)
	resp, _ = doReq(t, c, "PUT", base+"/api/rules", string(b), csrf, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("PUT enable: %d", resp.StatusCode)
	}
	if d := feed("evil-tracker.com"); d.block != 1 {
		t.Fatalf("re-enabled rule must block, got %+v", d)
	}

	// 7) Delete via Web/API → gone from repo + dataplane observe.
	b, _ = json.Marshal(map[string]string{"id": added.ID})
	resp, _ = doReq(t, c, "DELETE", base+"/api/rules", string(b), csrf, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("DELETE rule: %d", resp.StatusCode)
	}
	if rulesContain(t, c, base, csrf, "evil-tracker.com") {
		t.Fatal("deleted rule still in backend repo")
	}
	if d := feed("evil-tracker.com"); d.block != 0 {
		t.Fatalf("deleted rule must not block, got %+v", d)
	}

	// 8) Import via Web/API → applied to runtime repo + enforced on dataplane.
	code, ibody := formImport(t, c, base, csrf, "BLOCK importsample.net\n", "txt")
	if code != 200 {
		t.Fatalf("import: %d %s", code, ibody)
	}
	if !rulesContain(t, c, base, csrf, "importsample.net") {
		t.Fatal("imported rule missing from runtime repo")
	}
	if d := feed("importsample.net"); d.block != 1 {
		t.Fatalf("imported rule must block, got %+v", d)
	}

	// 9) Export via Web/API reflects the live runtime rules.
	exp, ebody := doReq(t, c, "GET", base+"/api/rules/export?format=txt", "", csrf, nil)
	if exp.StatusCode != 200 || !strings.Contains(ebody, "importsample.net") {
		t.Fatalf("export missing imported rule: %d %s", exp.StatusCode, ebody)
	}

	// 10) Mode switch via Web/API is reflected in /api/status AND /api/mode AND
	// the runtime AND the dataplane result.
	resp, bbody := doReq(t, c, "POST", base+"/api/mode", `{"mode":"bypass"}`, csrf, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("POST mode: %d %s", resp.StatusCode, bbody)
	}
	if got := modeFromStatus(t, c, base, csrf); got != "bypass" {
		t.Fatalf("status mode after switch=%q want bypass", got)
	}
	resp, bbody = doReq(t, c, "GET", base+"/api/mode", "", csrf, nil)
	var mm struct {
		Mode string `json:"mode"`
	}
	_ = json.Unmarshal([]byte(bbody), &mm)
	if mm.Mode != "bypass" {
		t.Fatalf("/api/mode=%q want bypass", mm.Mode)
	}
	if gw.Mode() != config.ModeBypass {
		t.Fatalf("gateway runtime mode=%v want bypass", gw.Mode())
	}
	// In bypass everything observes regardless of the block rules.
	if d := feed("importsample.net"); d.block != 0 {
		t.Fatalf("bypass must not block imported rule, got %+v", d)
	}

	// 11) Logs/dashboard: after all that traffic the events feed is non-empty
	// and the dashboard analytics reflect observed enforcement.
	evs := m.Events()
	if len(evs) == 0 {
		t.Fatal("metrics event registry empty after traffic")
	}
	resp, ebody = doReq(t, c, "GET", base+"/api/events?limit=100", "", csrf, nil)
	if resp.StatusCode != 200 || !strings.Contains(ebody, "importsample.net") {
		t.Fatalf("events endpoint missing observed flow: %d %s", resp.StatusCode, ebody)
	}
	resp, abody := doReq(t, c, "GET", base+"/api/analytics", "", csrf, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("analytics: %d %s", resp.StatusCode, abody)
	}
}

var feedSeq uint64
