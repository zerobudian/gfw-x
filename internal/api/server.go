package api

import (
	"embed"
	"encoding/json"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	"gfw-x/internal/config"
	"gfw-x/internal/gateway"
)

//go:embed dist/*
var dist embed.FS

// Server is the HTTP API / dashboard server.
type Server struct {
	gw   *gateway.Gateway
	cfg  *config.Config
	mux  *http.ServeMux
	auth *Auth
	sett *Settings
}

// New creates a server bound to a running gateway.
func New(gw *gateway.Gateway, cfg *config.Config) *Server {
	s := &Server{
		gw:   gw,
		cfg:  cfg,
		mux:  http.NewServeMux(),
		auth: NewAuth(&cfg.Server.Auth),
		sett: NewSettings(cfg.Default),
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/login", s.handleLogin)
	// Liveness probe must be reachable without credentials, otherwise
	// health.sh / Docker HEALTHCHECK / systemd all report failure.
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/metrics", s.handleMetrics)
	s.mux.Handle("/api/", s.requireAuth(http.HandlerFunc(s.apiHandler)))
	s.mux.Handle("/", s.staticHandler())
}

// handleMetrics exposes Prometheus text metrics scoped to the data plane.
// It is intentionally public (no auth) so scrapers do not need credentials.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = io.WriteString(w, s.gw.PrometheusText())
}

// apiHandler dispatches API subroutes.
func (s *Server) apiHandler(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/api")
	switch {
	case p == "/status":
		s.handleStatus(w, r)
	case p == "/health":
		s.handleHealth(w, r)
	case p == "/events":
		s.handleEvents(w, r)
	case p == "/top/domains":
		s.handleTopDomains(w, r)
	case p == "/top/reasons":
		s.handleTopReasons(w, r)
	case p == "/protocols":
		s.handleProtocols(w, r)
	case p == "/analytics":
		s.handleAnalytics(w, r)
	case p == "/traces":
		s.handleTraces(w, r)
	case p == "/shadow":
		s.handleShadow(w, r)
	case p == "/mode":
		s.handleMode(w, r)
	case p == "/rules":
		s.handleRules(w, r)
	case p == "/rules/search":
		s.handleRuleSearch(w, r)
	case p == "/rules/conflicts":
		s.handleRuleConflicts(w, r)
	case p == "/rules/dry-run":
		s.handleRuleDryRun(w, r)
	case p == "/rules/apply":
		s.handleRuleApply(w, r)
	case p == "/rules/rollback":
		s.handleRuleRollback(w, r)
	case p == "/rules/revisions":
		s.handleRuleRevisions(w, r)
	case strings.HasPrefix(p, "/rules/revisions/"):
		s.handleRuleRevisionGet(w, r)
	case p == "/rules/presets":
		s.handlePresets(w, r)
	case p == "/rules/import/preview":
		s.handleRuleImportPreview(w, r)
	case p == "/rules/import":
		s.handleRuleImport(w, r)
	case p == "/rules/export":
		s.handleRuleExport(w, r)
	case p == "/config":
		s.handleConfig(w, r)
	case p == "/settings/theme":
		s.handleSetTheme(w, r)
	case p == "/settings/lang":
		s.handleSetLang(w, r)
	case p == "/auth/status":
		s.handleAuthStatus(w, r)
	case p == "/detect":
		s.handleDetect(w, r)
	case p == "/export":
		s.handleExport(w, r)
	case p == "/export/logs":
		s.handleExportLogs(w, r)
	case p == "/export/config":
		s.handleExportConfig(w, r)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

// requireAuth wraps writes with CSRF and reads with token auth.
func (s *Server) requireAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.verify(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if !s.csrfGuard(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf verification failed"})
			return
		}
		next(w, r)
	})
}

func (s *Server) csrfGuard(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return s.auth.checkCSRF(r)
}

// staticHandler serves embedded SPA files with an index.html fallback.
func (s *Server) staticHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" || p == "." {
			p = "index.html"
		}
		// The embed directive roots embedded paths under "dist/".
		key := "dist/" + p
		data, err := dist.ReadFile(key)
		if err != nil {
			// SPA fallback (hash routing used, but be safe for deep links).
			data, err = dist.ReadFile("dist/index.html")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		} else {
			if ct := mime.TypeByExtension(path.Ext(p)); ct != "" {
				w.Header().Set("Content-Type", ct)
			}
		}
		_, _ = w.Write(data)
	})
}

// handleLogin authenticates and issues a session cookie + CSRF token.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	ip := s.auth.RemoteIP(r)
	if !s.auth.allowLogin(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many login attempts, retry later"})
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	data, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	_ = json.Unmarshal(data, &body)
	if !s.auth.enabled {
		// No auth required: still return a session for consistency.
		writeJSON(w, http.StatusOK, map[string]string{"ok": "true", "csrf": s.auth.CSRF()})
		return
	}
	// First-run / reset bootstrap: when no password hash is configured, expose a
	// setup signal instead of a working default credential.
	if !s.auth.PasswordConfigured() {
		if body.Username == "" || body.Password == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no admin password configured; set one to unlock the dashboard", "requires_setup": "true"})
			return
		}
		s.auth.SetPassword(body.Password, body.Username)
	}
	if body.Username != s.auth.username {
		s.auth.recordFailure(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	if ok, _ := s.auth.verifyPassword(body.Password); !ok {
		s.auth.recordFailure(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	s.auth.resetFailCount(ip)
	// Rotate the session so a fresh login invalidates any prior token, and
	// return the new CSRF token.
	newToken := s.auth.issueSession()
	sameSite := http.SameSiteStrictMode
	c := &http.Cookie{
		Name: "gfwx_session", Value: newToken, Path: "/",
		HttpOnly: true, SameSite: sameSite, MaxAge: int((12 * time.Hour).Seconds()),
		Secure: r.TLS != nil,
	}
	http.SetCookie(w, c)
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true", "csrf": s.auth.CSRF()})
}

// Listen starts the HTTP server and returns when it exits.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.cfg.Server.Listen)
	if err != nil {
		return err
	}
	log.Printf("GFW X dashboard listening on http://%s", s.cfg.Server.Listen)
	return http.Serve(ln, s.mux)
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readBody(r *http.Request) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, 4<<20))
}

func writeErr(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}
