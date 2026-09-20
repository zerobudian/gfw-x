package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"gfw-x/internal/config"
	"gfw-x/internal/export"
	"gfw-x/internal/rules"
	"gfw-x/internal/version"
)

// handleStatus returns aggregate dashboard state.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	snap := s.gw.Metrics().Snapshot()
	cl, slow := s.gw.Classifies()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":             s.gw.Mode(),
		"mode_valid":       config.ValidModes,
		"uptime_sec":       int(time.Since(s.gw.Uptime()).Seconds()),
		"throughput_bps":   s.gw.Metrics().Throughput(),
		"counters":         snap,
		"active_flows":     s.gw.Table().ActiveFlows(),
		"lookup_hits":      s.gw.Table().LookupHits(),
		"lookup_misses":    s.gw.Table().LookupMisses(),
		"classifies":       cl,
		"slow_path":        slow,
		"cpu_cores":        runtime.GOMAXPROCS(0),
		"memory_mb":        float64(m.HeapAlloc) / (1024 * 1024),
		"version":          version.Info(),
		"detections":       s.gw.Detector().Detections(),
		"theme":            s.sett.Theme(),
		"lang":             s.sett.Lang(),
		"log_degraded":     s.gw.LogStats(),
	})
}

// handleHealth returns liveness.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleEvents returns the in-memory live events.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	evs := s.gw.Metrics().Events()
	if len(evs) > limit {
		evs = evs[:limit]
	}
	writeJSON(w, http.StatusOK, evs)
}

func (s *Server) handleTopDomains(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.gw.Metrics().TopDomains(20))
}

func (s *Server) handleTopReasons(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.gw.Metrics().TopReasons(20))
}

func (s *Server) handleProtocols(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.gw.Metrics().ProtocolDist())
}

// handleAnalytics summarizes traffic analytics.
func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"top_domains": s.gw.Metrics().TopDomains(20),
		"top_reasons": s.gw.Metrics().TopReasons(20),
		"protocols":   s.gw.Metrics().ProtocolDist(),
	})
}

// handleMode reads (GET) and switches (POST) the run mode at runtime.
func (s *Server) handleMode(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]string{"mode": string(s.gw.Mode())})
		return
	}
	var body struct {
		Mode string `json:"mode"`
	}
	_ = decodeJSON(r, &body)
	m, err := config.ParseMode(body.Mode)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := s.gw.SetMode(m); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"mode": string(s.gw.Mode())})
}

// handleRules implements CRUD over the active rule repo.
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	repo := s.gw.Rules()
	switch {
	case r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, repo.All())
	case r.Method == http.MethodPost:
		var rule rules.Rule
		if err := decodeJSON(r, &rule); err != nil {
			writeErr(w, err)
			return
		}
		if err := repo.Add(&rule); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, rule)
	case r.Method == http.MethodPut:
		var rule rules.Rule
		if err := decodeJSON(r, &rule); err != nil {
			writeErr(w, err)
			return
		}
		if err := repo.Update(&rule); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, rule)
	case r.Method == http.MethodDelete:
		var body struct {
			ID string `json:"id"`
		}
		_ = decodeJSON(r, &body)
		if err := repo.Delete(body.ID); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"deleted": body.ID})
	default:
		writeErr(w, fmt.Errorf("unsupported method"))
	}
}

func (s *Server) handleRuleSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(r.URL.Query().Get("q"))
	out := []*rules.Rule{}
	for _, rl := range s.gw.Rules().All() {
		if q == "" || strings.Contains(strings.ToLower(rl.Label()), q) ||
			strings.Contains(strings.ToLower(rl.ID), q) ||
			strings.Contains(strings.ToLower(rl.Category), q) {
			out = append(out, rl)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleRuleConflicts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.gw.Rules().Conflicts())
}

func (s *Server) handlePresets(w http.ResponseWriter, r *http.Request) {
	repo := s.gw.Rules()
	if r.Method == http.MethodGet {
		out := map[string]string{}
		for _, n := range rules.PresetNames() {
			p, _ := rules.PresetBy(n)
			out[n] = p.Desc
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	var body struct {
		Preset string `json:"preset"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, err)
		return
	}
	p, ok := rules.PresetBy(body.Preset)
	if !ok {
		writeErr(w, fmt.Errorf("unknown preset %q", body.Preset))
		return
	}
	repo.Replace(p.Rules)
	writeJSON(w, http.StatusOK, map[string]any{"preset": p.Name, "rules": len(p.Rules)})
}

// Import pipeline: parse → validate → conflict → preview → apply.
func (s *Server) handleRuleImport(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("content")
	format := r.FormValue("format")
	if format == "" {
		format = guessFormat([]byte(data))
	}
	if data == "" {
		// allow file upload
		f, _, err := r.FormFile("file")
		if err == nil {
			defer f.Close()
			b, _ := readAll(f, 4<<20)
			data = string(b)
		}
	}
	imported, err := rules.ParseBytes([]byte(data), format)
	if err != nil {
		writeErr(w, err)
		return
	}
	// conflict detection vs current set
	conflicts := mergeConflicts(s.gw.Rules().All(), imported)
	if len(conflicts) > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "conflicts detected", "conflicts": conflicts, "imported": imported, "applied": false})
		return
	}
	s.gw.Rules().Replace(imported)
	writeJSON(w, http.StatusOK, map[string]any{"imported": len(imported), "applied": true})
}

// handleRuleImportPreview runs parse/validate + preview without applying.
func (s *Server) handleRuleImportPreview(w http.ResponseWriter, r *http.Request) {
	data := r.FormValue("content")
	if data == "" {
		writeErr(w, fmt.Errorf("missing content"))
		return
	}
	parsed, err := rules.ParseBytes([]byte(data), guessFormat([]byte(data)))
	if err != nil {
		writeErr(w, err)
		return
	}
	conflicts := mergeConflicts(s.gw.Rules().All(), parsed)
	writeJSON(w, http.StatusOK, map[string]any{
		"parsed": parsed, "count": len(parsed),
		"conflicts": conflicts,
		"applied":   false,
	})
}

func (s *Server) handleRuleExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format") // yaml|json|txt
	var data []byte
	switch format {
	case "json":
		data, _ = rules.MarshalJSON(s.gw.Rules().All())
		w.Header().Set("Content-Type", "application/json")
	case "txt":
		data = []byte(rules.MarshalTXT(s.gw.Rules().All()))
		w.Header().Set("Content-Type", "text/plain")
	default:
		data, _ = rules.MarshalYAML(s.gw.Rules().All())
		w.Header().Set("Content-Type", "application/x-yaml")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// handleConfig returns or updates the config.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, s.cfg)
		return
	}
	// allow runtime edits of safe subset (mode already separate).
	writeJSON(w, http.StatusOK, map[string]string{"note": "runtime config is not persisted"})
}

func (s *Server) handleSetTheme(w http.ResponseWriter, r *http.Request) {
	var body struct{ Theme string `json:"theme"` }
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, err)
		return
	}
	s.sett.SetTheme(config.Theme(strings.ToLower(body.Theme)))
	writeJSON(w, http.StatusOK, map[string]string{"theme": string(s.sett.Theme())})
}

func (s *Server) handleSetLang(w http.ResponseWriter, r *http.Request) {
	var body struct{ Lang string `json:"lang"` }
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, err)
		return
	}
	s.sett.SetLang(config.Lang(strings.ToLower(body.Lang)))
	writeJSON(w, http.StatusOK, map[string]string{"lang": string(s.sett.Lang())})
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": s.auth.Enabled(),
		"csrf":    s.auth.CSRF(),
		"version": version.Short(),
	})
}

func (s *Server) handleDetect(w http.ResponseWriter, r *http.Request) {
	det := s.gw.Detector()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":    det.Enabled(),
		"threshold":  det.Threshold(),
		"auto_apply": det.AutoApply(),
		"detections": det.Detections(),
	})
}

// handleExport streams the diagnostic ZIP.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	redact := r.URL.Query().Get("redact") == "1"
	b := &export.Bundle{
		Config:  s.cfg,
		Rules:   s.gw.Rules().All(),
		Metrics: s.gw.Metrics(),
		Format:  s.cfg.Logging.Format,
	}
	dir, _ := os.MkdirTemp("", "gfwx-export-*")
	defer os.RemoveAll(dir)
	path, err := export.Run(b, export.Options{ZIP: true, Redact: redact, OutDir: dir})
	if err != nil {
		writeErr(w, err)
		return
	}
	http.ServeFile(w, r, path)
}

func (s *Server) handleExportRules(w http.ResponseWriter, r *http.Request) {
	s.handleRuleExport(w, r)
}

func (s *Server) handleExportConfig(w http.ResponseWriter, r *http.Request) {
	b := &export.Bundle{Config: s.cfg, Rules: s.gw.Rules().All(), Metrics: s.gw.Metrics(), Format: s.cfg.Logging.Format}
	dir, _ := os.MkdirTemp("", "gfwx-cfg-*")
	defer os.RemoveAll(dir)
	path, _ := export.Run(b, export.Options{ZIP: true, Redact: r.URL.Query().Get("redact") == "1", OutDir: dir})
	http.ServeFile(w, r, path)
}

func (s *Server) handleExportLogs(w http.ResponseWriter, r *http.Request) {
	b := &export.Bundle{Config: s.cfg, Rules: s.gw.Rules().All(), Metrics: s.gw.Metrics(), Format: s.cfg.Logging.Format}
	dir, _ := os.MkdirTemp("", "gfwx-logs-*")
	defer os.RemoveAll(dir)
	path, _ := export.Run(b, export.Options{ZIP: true, Redact: r.URL.Query().Get("redact") == "1", OutDir: dir})
	http.ServeFile(w, r, path)
}

// --- small helpers ---

func decodeJSON(r *http.Request, v any) error {
	data, err := readBody(r)
	if err != nil {
		return err
	}
	return jsonUnmarshal(data, v)
}

func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func guessFormat(data []byte) string {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{") {
		return "json"
	}
	if strings.Contains(trimmed, "rules:") {
		return "yaml"
	}
	return "txt"
}

func readAll(f io.Reader, sz int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(f, sz))
}

// mergeConflicts finds overlaps between current and incoming rules.
func mergeConflicts(current, incoming []*rules.Rule) []rules.Conflict {
	var out []rules.Conflict
	seen := map[string]bool{}
	for i := range incoming {
		for j := range current {
			ok, field := incoming[i].ConflictsWith(current[j])
			if ok {
				k := field + ":" + string(incoming[i].Kind) + ":" + string(current[j].Kind)
				if !seen[k] {
					seen[k] = true
					out = append(out, rules.Conflict{A: incoming[i], B: current[j], Field: field, Value: conflictValue(incoming[i], current[j])})
				}
			}
		}
	}
	return out
}

func conflictValue(a, b *rules.Rule) string {
	for _, am := range a.Matchers {
		for _, bm := range b.Matchers {
			if am.Field == bm.Field && strings.EqualFold(am.Value, bm.Value) {
				return am.Value
			}
		}
	}
	return ""
}