package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"gfw-x/internal/config"
)

// sessionTTL is how long a login session stays valid before re-authentication
// is required. Sessions are rotated on every successful login.
const sessionTTL = 12 * time.Hour

// loginWindow / loginMax bound failed-login attempts per source IP (the
// simplest effective rate limit: a fixed window + lockout).
const (
	loginWindow = time.Minute
	loginMax    = 10
	loginLock   = 30 * time.Second
)

// failCounter tracks failed-login attempts for one source address.
type failCounter struct {
	count    int
	resetAt  time.Time
	lockedAt time.Time
}

// Auth implements session auth + CSRF double-submit protection.
type Auth struct {
	mu           sync.Mutex
	enabled      bool
	username     string
	passwordHash string
	token        string // admin session token
	csrfToken    string
	tokenExpiry  time.Time

	fails map[string]*failCounter
}

// NewAuth builds an auth layer from config.
func NewAuth(cfg *config.Auth) *Auth {
	token := cfg.SessionToken
	if token == "" {
		token = randomToken()
	}
	a := &Auth{
		enabled:      cfg.Enabled,
		username:     cfg.Username,
		passwordHash: cfg.PasswordHash,
		token:        token,
		csrfToken:    randomToken(),
		tokenExpiry:  time.Now().Add(sessionTTL),
		fails:        map[string]*failCounter{},
	}
	return a
}

// Enabled reports whether auth is on.
func (a *Auth) Enabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.enabled
}

// PasswordIsArgon2 reports whether the configured hash uses the modern scheme.
func (a *Auth) PasswordIsArgon2() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return isArgon2Hash(a.passwordHash)
}

// PasswordConfigured reports whether an admin password hash is set at all.
func (a *Auth) PasswordConfigured() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.passwordHash != ""
}

// resetFailCount clears the rate-limit state for a source IP on success.
func (a *Auth) resetFailCount(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.fails, ip)
}

// SetPassword stores an Argon2id hash of the new password.
func (a *Auth) SetPassword(password string, username string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if username != "" {
		a.username = username
	}
	if password != "" {
		a.passwordHash = hashPassword(password)
	}
}

// CSRF returns the current CSRF token.
func (a *Auth) CSRF() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.csrfToken
}

// verifyPassword checks a plaintext password, transparently upgrading a legacy
// SHA-256 hash to Argon2id on success (migration path) so existing configs are
// not locked out.
func (a *Auth) verifyPassword(pw string) (bool, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	upgraded, ok := verifyAndUpgrade(pw, a.passwordHash)
	if ok && upgraded != "" {
		// Persist the migration for the rest of this process runtime.
		a.passwordHash = upgraded
	}
	return ok, upgraded
}

// allowLogin enforces the failed-login rate limit per source IP.
func (a *Auth) allowLogin(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.enabled {
		return true
	}
	c, ok := a.fails[ip]
	if !ok {
		c = &failCounter{}
		a.fails[ip] = c
	}
	now := time.Now()
	if c.resetAt.IsZero() || now.After(c.resetAt) {
		c.count = 0
		c.lockedAt = time.Time{}
		c.resetAt = now.Add(loginWindow)
	}
	if now.Before(c.lockedAt) {
		return false
	}
	if c.count >= loginMax {
		c.lockedAt = now.Add(loginLock)
		c.count = 0
		c.resetAt = now.Add(loginWindow)
		return false
	}
	return true
}

// recordFailure increments the failed-login counter for a source IP.
func (a *Auth) recordFailure(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.fails[ip]
	if !ok {
		return
	}
	c.count++
	if c.count >= loginMax {
		c.lockedAt = time.Now().Add(loginLock)
		c.count = 0
		c.resetAt = time.Now().Add(loginWindow)
	}
}

// issueSession rotates the session token and resets its expiry (each successful
// login invalidates the previous session and yields a fresh CSRF token).
func (a *Auth) issueSession() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.token = randomToken()
	a.csrfToken = randomToken()
	a.tokenExpiry = time.Now().Add(sessionTTL)
	return a.token
}

// sessionValid reports whether the supplied session token is valid and unexpired.
func (a *Auth) sessionValid(got string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if time.Now().After(a.tokenExpiry) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) == 1
}

// verify returns true if a request carries a valid Bearer token or session.
func (a *Auth) verify(r *http.Request) bool {
	if !a.enabled {
		return true
	}
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") && a.sessionValid(strings.TrimPrefix(h, "Bearer ")) {
		return true
	}
	ck, err := r.Cookie("gfwx_session")
	if err == nil && a.sessionValid(ck.Value) {
		return true
	}
	return false
}

// RemoteIP extracts a best-effort client IP from the request.
func (a *Auth) RemoteIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			xff = xff[:i]
		}
		if ip := net.ParseIP(strings.TrimSpace(xff)); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// checkCSRF validates Origin/Referer and the CSRF token for mutations.
func (a *Auth) checkCSRF(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	if !a.enabled {
		return true
	}
	// Origin check.
	origin := r.Header.Get("Origin")
	if origin != "" {
		if !allowedOrigin(origin) {
			return false
		}
	}
	referer := r.Header.Get("Referer")
	if referer != "" {
		if !allowedReferrer(referer) {
			return false
		}
	}
	// Double-submit CSRF token.
	headerTok := r.Header.Get("X-CSRF-Token")
	if headerTok == "" {
		headerTok = r.URL.Query().Get("csrf")
	}
	return subtle.ConstantTimeCompare([]byte(headerTok), []byte(a.csrfToken)) == 1
}

func allowedOrigin(origin string) bool {
	// Parse so a scheme-ful but port-less origin and IPv6 literals are handled
	// without slicing a possibly-absent ':' (which previously panicked).
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return isLocalHostname(u.Hostname())
}

func allowedReferrer(ref string) bool { return allowedOrigin(ref) }

func isLocalHostname(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4[0] == 10 ||
			(v4[0] == 192 && v4[1] == 168) ||
			(v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31) // full 172.16.0.0/12
	}
	return ip.IsLoopback()
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "000000000000000000000000"
	}
	return hex.EncodeToString(b)
}

// randomToken returns a 32-byte random hex session / CSRF token.
func randomToken() string { return randomHex(32) }

// Settings holds dashboard preferences (theme/lang), persisted in memory.
type Settings struct {
	mu    sync.RWMutex
	theme config.Theme
	lang  config.Lang
}

// NewSettings returns settings with defaults.
func NewSettings(d config.Defaults) *Settings {
	return &Settings{theme: d.Theme, lang: d.Lang}
}

func (s *Settings) Theme() config.Theme {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.theme
}

func (s *Settings) SetTheme(t config.Theme) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.theme = t
}

func (s *Settings) Lang() config.Lang {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lang
}

func (s *Settings) SetLang(l config.Lang) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lang = l
}
