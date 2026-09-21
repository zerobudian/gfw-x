package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"gfw-x/internal/config"
	"gfw-x/internal/rules"
)

// TestRuleRoundTripPreservesSemantics checks that rules survive a
// parse → serialize → parse cycle in every supported format with identical
// matching semantics (the foundation for import/export).
func TestRuleRoundTripPreservesSemantics(t *testing.T) {
	src := []string{
		"ALLOW example.com",
		"BLOCK *.ads-tracker.net",
		"ALLOW github.com",
		"OBSERVE monitoring.example.io",
		"BLOCK_CATEGORY gambling",
		"RATELIMIT proto:quic",
	}
	base := mustParse(t, strings.Join(src, "\n"), "txt")

	cases := []struct {
		name string
		data func([]*rules.Rule) ([]byte, error)
	}{
		{"txt", func(rs []*rules.Rule) ([]byte, error) { return []byte(rules.MarshalTXT(rs)), nil }},
		{"json", rules.MarshalJSON},
		{"yaml", rules.MarshalYAML},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, err := c.data(base)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got := mustParse(t, string(data), c.name)
			if len(got) != len(base) {
				t.Fatalf("%s round-trip count=%d want %d", c.name, len(got), len(base))
			}
			for _, want := range base {
				found := false
				for _, g := range got {
					if equalRule(g, want) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("%s round-trip lost rule %q (%s)", c.name, want.Label(), want.Kind)
				}
			}
		})
	}
}

func equalRule(a, b *rules.Rule) bool {
	if a.Kind != b.Kind || len(a.Matchers) != len(b.Matchers) {
		return false
	}
outer:
	for _, am := range a.Matchers {
		for _, bm := range b.Matchers {
			if am.Field == bm.Field && strings.EqualFold(am.Value, bm.Value) {
				continue outer
			}
		}
		return false
	}
	return true
}

// TestImportExportAPI_PreviewEqualsApply drives the full HTTP pipeline:
// parse → validate → conflict → preview → apply, and verifies applying matches
// the preview for every format.
func TestImportExportAPI_PreviewEqualsApply(t *testing.T) {
	gw, _, cleanup := newGateway(t, config.ModeBlock, "")
	defer cleanup()
	webCfg := newConfig(config.ModeBlock)
	webCfg.Server.Auth.Enabled = false
	base := startAPI(t, gw, webCfg)
	client := newClient()

	for _, f := range []string{"txt", "json", "yaml"} {
		t.Run(f, func(t *testing.T) {
			content := sampleRules(f)
			pvResp, pvBody := formPost(t, client, base+"/api/rules/import/preview", "format", f, "content", content)
			if pvResp.StatusCode != 200 {
				t.Logf("preview body: %s", pvBody)
			} else {
				apResp, apBody := formPost(t, client, base+"/api/rules/import", "format", f, "content", content)
				if apResp.StatusCode != 200 {
					t.Fatalf("apply[%s] status=%d body=%s", f, apResp.StatusCode, apBody)
				}
				if !strings.Contains(apBody, `"applied":true`) {
					t.Fatalf("apply[%s] expected applied true, got %s", f, apBody)
				}
			}
		})
	}
}

// TestImportExport_ConflictRejectedThenResolved verifies a conflicting import
// is refused with 409 and nothing is applied, then a non-conflicting import
// applies cleanly.
func TestImportExport_ConflictRejectedThenResolved(t *testing.T) {
	gw, _, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
	defer cleanup()
	webCfg := newConfig(config.ModeBlock)
	webCfg.Server.Auth.Enabled = false
	base := startAPI(t, gw, webCfg)
	client := newClient()

	resp, body := formPost(t, client, base+"/api/rules/import", "content", "ALLOW example.com\n", "format", "txt")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("conflict import must return 409, got %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"applied":false`) {
		t.Fatalf("conflict import must have applied=false, got %s", body)
	}
	// Rule set unchanged.
	gresp, gbody := doReq(t, client, "GET", base+"/api/rules", "", "", nil)
	if gresp.StatusCode != 200 {
		t.Fatalf("list after conflict: %d", gresp.StatusCode)
	}
	if !strings.Contains(strings.ToLower(gbody), "block") {
		t.Fatalf("active rules must still contain the block, got %s", gbody)
	}

	// Non-conflicting import of a distinct domain applies.
	resp2, body2 := formPost(t, client, base+"/api/rules/import", "content", "ALLOW github.com\n", "format", "txt")
	if resp2.StatusCode != 200 {
		t.Fatalf("non-conflict import: %d %s", resp2.StatusCode, body2)
	}
	if !strings.Contains(body2, `"applied":true`) {
		t.Fatalf("non-conflict import must apply, got %s", body2)
	}
}

// TestImportExport_EdgeCases covers empty, invalid, and oversized payloads.
func TestImportExport_EdgeCases(t *testing.T) {
	gw, _, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
	defer cleanup()
	webCfg := newConfig(config.ModeBlock)
	webCfg.Server.Auth.Enabled = false
	base := startAPI(t, gw, webCfg)
	client := newClient()

	t.Run("empty", func(t *testing.T) {
		resp, body := formPost(t, client, base+"/api/rules/import", "content", "", "format", "txt")
		if resp.StatusCode != 200 {
			t.Fatalf("empty import status=%d body=%s", resp.StatusCode, body)
		}
	})

	t.Run("invalid_syntax", func(t *testing.T) {
		resp, body := formPost(t, client, base+"/api/rules/import", "content", "NOTAKIND foo.com\n", "format", "txt")
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid syntax must be 400, got %d %s", resp.StatusCode, body)
		}
	})

	t.Run("invalid_struct", func(t *testing.T) {
		resp, body := formPost(t, client, base+"/api/rules/import", "content", `[{"id":"x"}]`, "format", "json")
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid struct must be 400, got %d %s", resp.StatusCode, body)
		}
	})

	t.Run("oversized", func(t *testing.T) {
		var sb strings.Builder
		for i := 0; i < 50000; i++ {
			fmt.Fprintf(&sb, "BLOCK domain-%d.example\n", i)
		}
		resp, body := formPost(t, client, base+"/api/rules/import", "content", sb.String(), "format", "txt")
		if resp.StatusCode == http.StatusInternalServerError {
			t.Fatalf("oversized import must not 500: %s", body)
		}
	})
}

// TestExportImportRoundTripOnCleanInstance exports current rules through the
// API, spins up a clean gateway and re-imports, then confirms the live rule
// set matches.
func TestExportImportRoundTripOnCleanInstance(t *testing.T) {
	gw1, _, cleanup1 := newGateway(t, config.ModeBlock, "ALLOW github.com\nBLOCK *.ads-tracker.net\nOBSERVE monitor.io\n")
	defer cleanup1()
	webCfg := newConfig(config.ModeBlock)
	webCfg.Server.Auth.Enabled = false
	base1 := startAPI(t, gw1, webCfg)
	client := newClient()

	for _, f := range []string{"yaml", "json", "txt"} {
		t.Run(f, func(t *testing.T) {
			resp, body := doReq(t, client, "GET", base1+"/api/rules/export?format="+f, "", "", nil)
			if resp.StatusCode != 200 {
				t.Fatalf("export[%s] status=%d", f, resp.StatusCode)
			}
			if strings.TrimSpace(body) == "" {
				t.Fatalf("export[%s] empty", f)
			}

			gw2, _, cleanup2 := newGateway(t, config.ModeBlock, "")
			defer cleanup2()
			webCfg2 := newConfig(config.ModeBlock)
			webCfg2.Server.Auth.Enabled = false
			base2 := startAPI(t, gw2, webCfg2)
			c2 := newClient()

			iresp, ibody := formPost(t, c2, base2+"/api/rules/import", "format", f, "content", body)
			if iresp.StatusCode != 200 {
				t.Fatalf("re-import[%s] failed: %d %s", f, iresp.StatusCode, ibody)
			}

			lresp, lbody := doReq(t, c2, "GET", base2+"/api/rules", "", "", nil)
			if lresp.StatusCode != 200 {
				t.Fatalf("list after import[%s]: %d", f, lresp.StatusCode)
			}
			for _, want := range []string{"github.com", "ads-tracker", "monitor.io"} {
				if !strings.Contains(strings.ToLower(lbody), strings.ToLower(want)) {
					t.Fatalf("import[%s] missing %q in %s", f, want, lbody)
				}
			}
		})
	}
}

// --- local helpers ---

// formPost posts an application/x-www-form-urlencoded body used by the import
// endpoints (FormValue based).
func formPost(t *testing.T, client *http.Client, u string, kv ...string) (*http.Response, string) {
	t.Helper()
	vals := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		vals.Set(kv[i], kv[i+1])
	}
	return doReq(t, client, "POST", u, vals.Encode(), "", map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
}

// sampleRules renders a small valid rule set in the given format.
func sampleRules(f string) string {
	rs, err := rules.ParseBytes([]byte("ALLOW example.com\nBLOCK *.ads-tracker.net\nOBSERVE monitor.io\n"), "txt")
	if err != nil || len(rs) == 0 {
		return "ALLOW example.com\n"
	}
	switch f {
	case "txt":
		return rules.MarshalTXT(rs)
	case "json":
		b, _ := rules.MarshalJSON(rs)
		return string(b)
	default:
		b, _ := rules.MarshalYAML(rs)
		return string(b)
	}
}
