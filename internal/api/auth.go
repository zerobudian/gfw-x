package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"gfw-x/internal/config"
)

// Auth implements session auth + CSRF double-submit protection.
type Auth struct {
	mu           sync.Mutex
	enabled      bool
	username     string
	passwordHash string
	token        string // admin session token
	csrfToken    string
}

// NewAuth builds an auth layer from config.
func NewAuth(cfg *config.Auth) *Auth {
	a := &Auth{
		enabled:      cfg.Enabled,
		username:     cfg.Username,
		passwordHash: cfg.PasswordHash,
		token:        cfg.SessionToken,
		csrfToken:    randomHex(16),
	}
	if a.token == "" {
		a.token = randomHex(24)
	}
	return a
}

// Enabled reports whether auth is on.
func (a *Auth) Enabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.enabled
}

// SetPassword stores a salted hash of the new password.
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

// HashPassword computes the salted SHA-256 used to store admin passwords.
func hashPassword(pw string) string {
	salt := "gfw-x-static-salt" // non-secret diversification salt
	inner := sha256.Sum256([]byte(salt + pw))
	outer := sha256.Sum256([]byte(string(inner[:]) + salt))
	return hex.EncodeToString(outer[:])
}

// verifyPassword checks a plaintext password against the stored hash.
func (a *Auth) verifyPassword(pw string) bool {
	got := hashPassword(pw)
	want := a.passwordHash
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// verify returns true if a request carries a valid Bearer token or session.
func (a *Auth) verify(r *http.Request) bool {
	if !a.enabled {
		return true
	}
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") && subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(h, "Bearer ")), []byte(a.token)) == 1 {
		return true
	}
	ck, err := r.Cookie("gfwx_session")
	if err == nil && subtle.ConstantTimeCompare([]byte(ck.Value), []byte(a.token)) == 1 {
		return true
	}
	return false
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