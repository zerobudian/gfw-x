package integration

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"gfw-x/internal/config"
	"gfw-x/internal/gateway"
)

// startAuthedAPI brings up the API with admin auth ENABLED (default password
// "admin"). Returns base URL, a raw session token (usable as Bearer or cookie),
// and the CSRF token.
func startAuthedAPI(t *testing.T, gw *gateway.Gateway) (base, token, csrf string) {
	t.Helper()
	webCfg := newConfig(config.ModeBlock)
	base = startAPI(t, gw, webCfg)
	token, csrf = manualLogin(t, base, "admin", "admin")
	return base, token, csrf
}

// manualLogin posts credentials and returns the raw session token (parsed from
// the Set-Cookie header) plus the CSRF token from the JSON body.
func manualLogin(t *testing.T, base, user, pass string) (token, csrf string) {
	t.Helper()
	c := newClient()
	bodyJSON := fmt.Sprintf(`{"username":%q,"password":%q}`, user, pass)
	resp, body := doReq(t, c, "POST", base+"/api/login", bodyJSON, "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("login(%s) status=%d body=%s", user, resp.StatusCode, body)
	}
	var out struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	for _, sc := range resp.Header["Set-Cookie"] {
		if strings.HasPrefix(sc, "gfwx_session=") {
			v := strings.TrimPrefix(sc, "gfwx_session=")
			if i := strings.Index(v, ";"); i >= 0 {
				v = v[:i]
			}
			return v, out.CSRF
		}
	}
	t.Fatalf("login did not set session cookie: %s", body)
	return "", out.CSRF
}

// TestAuth_LoginAndToken covers valid login, invalid password, missing and
// invalid tokens, cookie and Bearer auth — no auth bypass allowed.
func TestAuth_LoginAndToken(t *testing.T) {
	gw, _, cleanup := newGateway(t, config.ModeBlock, "")
	defer cleanup()
	base, _, _ := startAuthedAPI(t, gw)

	t.Run("valid_login_sets_cookie", func(t *testing.T) {
		c := newClient()
		resp, body := doReq(t, c, "POST", base+"/api/login", `{"username":"admin","password":"admin"}`, "", nil)
		if resp.StatusCode != 200 {
			t.Fatalf("login status=%d body=%s", resp.StatusCode, body)
		}
		if !strings.Contains(strings.Join(resp.Header["Set-Cookie"], ";"), "gfwx_session=") {
			t.Fatal("login must set session cookie")
		}
	})

	t.Run("invalid_password_401", func(t *testing.T) {
		c := newClient()
		resp, body := doReq(t, c, "POST", base+"/api/login", `{"username":"admin","password":"wrong"}`, "", nil)
		if resp.StatusCode != 401 {
			t.Fatalf("invalid password must be 401, got %d %s", resp.StatusCode, body)
		}
	})

	t.Run("missing_token_401", func(t *testing.T) {
		c := newClient()
		resp, _ := doReq(t, c, "GET", base+"/api/status", "", "", nil)
		if resp.StatusCode != 401 {
			t.Fatalf("missing token must be 401, got %d", resp.StatusCode)
		}
	})

	t.Run("invalid_bearer_401", func(t *testing.T) {
		c := newClient()
		resp, _ := doReq(t, c, "GET", base+"/api/status", "", "", map[string]string{"Authorization": "Bearer not-a-real-token"})
		if resp.StatusCode != 401 {
			t.Fatalf("invalid bearer must be 401, got %d", resp.StatusCode)
		}
	})

	t.Run("valid_bearer_200", func(t *testing.T) {
		// Session rotation means a token captured before another login is
		// invalidated. Log in fresh to obtain a currently-valid token.
		c := newClient()
		freshTok, _ := manualLogin(t, base, "admin", "admin")
		resp, body := doReq(t, c, "GET", base+"/api/status", "", "", map[string]string{"Authorization": "Bearer " + freshTok})
		if resp.StatusCode != 200 {
			t.Fatalf("valid bearer must be 200, got %d %s", resp.StatusCode, body)
		}
	})

	t.Run("valid_cookie_200", func(t *testing.T) {
		c, _ := login(t, base)
		resp, body := doReq(t, c, "GET", base+"/api/status", "", "", nil)
		if resp.StatusCode != 200 {
			t.Fatalf("cookie session must be 200, got %d %s", resp.StatusCode, body)
		}
	})
}

// TestAuth_CSRF protects mutations: missing/invalid CSRF and hostile origins
// are refused; valid sessions + CSRF + same-origin succeed. No CSRF bypass.
func TestAuth_CSRF(t *testing.T) {
	gw, _, cleanup := newGateway(t, config.ModeBlock, "")
	defer cleanup()
	base, token, csrf := startAuthedAPI(t, gw)
	auth := map[string]string{"Authorization": "Bearer " + token}

	themeBody := `{"theme":"dark"}`

	t.Run("get_skips_csrf", func(t *testing.T) {
		c := newClient()
		resp, body := doReq(t, c, "GET", base+"/api/rules", "", "", auth)
		if resp.StatusCode != 200 {
			t.Fatalf("GET with bearer must be 200, got %d %s", resp.StatusCode, body)
		}
	})

	t.Run("missing_csrf_403", func(t *testing.T) {
		c := newClient()
		resp, _ := doReq(t, c, "POST", base+"/api/settings/theme", themeBody, "", auth)
		if resp.StatusCode != 403 {
			t.Fatalf("mutation without CSRF must be 403, got %d", resp.StatusCode)
		}
	})

	t.Run("invalid_csrf_403", func(t *testing.T) {
		c := newClient()
		resp, _ := doReq(t, c, "POST", base+"/api/settings/theme", themeBody, "wrong-csrf", auth)
		if resp.StatusCode != 403 {
			t.Fatalf("mutation with wrong CSRF must be 403, got %d", resp.StatusCode)
		}
	})

	t.Run("valid_csrf_200", func(t *testing.T) {
		c := newClient()
		resp, body := doReq(t, c, "POST", base+"/api/settings/theme", themeBody, csrf, auth)
		if resp.StatusCode != 200 {
			t.Fatalf("valid CSRF must be 200, got %d %s", resp.StatusCode, body)
		}
	})

	t.Run("external_origin_403", func(t *testing.T) {
		c := newClient()
		hdr := map[string]string{"Authorization": "Bearer " + token, "Origin": "http://evil.example"}
		resp, body := doReq(t, c, "POST", base+"/api/settings/theme", themeBody, csrf, hdr)
		if resp.StatusCode != 403 {
			t.Fatalf("external origin must be 403, got %d %s", resp.StatusCode, body)
		}
	})

	t.Run("origin_blocked_no_port_no_crash", func(t *testing.T) {
		// Regression: Origin "http://blocked" (no port) previously caused a
		// panicking slice in allowedOrigin. Must be cleanly rejected, never 5xx.
		c := newClient()
		hdr := map[string]string{"Authorization": "Bearer " + token, "Origin": "http://blocked"}
		resp, body := doReq(t, c, "POST", base+"/api/settings/theme", themeBody, csrf, hdr)
		if resp.StatusCode != 403 {
			t.Fatalf("Origin http://blocked must be rejected (403), got %d %s", resp.StatusCode, body)
		}
	})

	t.Run("local_origin_200", func(t *testing.T) {
		c := newClient()
		hdr := map[string]string{"Authorization": "Bearer " + token, "Origin": "http://127.0.0.1:8080"}
		resp, body := doReq(t, c, "POST", base+"/api/settings/theme", themeBody, csrf, hdr)
		if resp.StatusCode != 200 {
			t.Fatalf("localhost origin must be 200, got %d %s", resp.StatusCode, body)
		}
	})

	t.Run("ipv6_origin_200", func(t *testing.T) {
		c := newClient()
		hdr := map[string]string{"Authorization": "Bearer " + token, "Origin": "http://[::1]:8080"}
		resp, body := doReq(t, c, "POST", base+"/api/settings/theme", themeBody, csrf, hdr)
		if resp.StatusCode != 200 {
			t.Fatalf("ipv6 loopback origin must be 200, got %d %s", resp.StatusCode, body)
		}
	})

	t.Run("private_lan_origin_200", func(t *testing.T) {
		c := newClient()
		hdr := map[string]string{"Authorization": "Bearer " + token, "Origin": "http://192.168.1.10:8080"}
		resp, body := doReq(t, c, "POST", base+"/api/settings/theme", themeBody, csrf, hdr)
		if resp.StatusCode != 200 {
			t.Fatalf("private lan origin must be 200, got %d %s", resp.StatusCode, body)
		}
	})

	t.Run("public_ip_origin_403", func(t *testing.T) {
		c := newClient()
		hdr := map[string]string{"Authorization": "Bearer " + token, "Origin": "http://8.8.8.8:8080"}
		resp, body := doReq(t, c, "POST", base+"/api/settings/theme", themeBody, csrf, hdr)
		if resp.StatusCode != 403 {
			t.Fatalf("public ip origin must be 403, got %d %s", resp.StatusCode, body)
		}
	})

	t.Run("no_panic_after_origin_attacks", func(t *testing.T) {
		c := newClient()
		resp, _ := doReq(t, c, "GET", base+"/api/status", "", "", auth)
		if resp.StatusCode != 200 {
			t.Fatalf("server must survive origin attacks, got %d", resp.StatusCode)
		}
	})
}

// TestAuth_NoBypass ensures protected state (rules, mode, events) cannot be
// read without valid credentials.
func TestAuth_NoBypass(t *testing.T) {
	gw, _, cleanup := newGateway(t, config.ModeBlock, "")
	defer cleanup()
	base, _, _ := startAuthedAPI(t, gw)
	anon := newClient()

	for _, ep := range []string{"/api/status", "/api/rules", "/api/mode", "/api/events", "/api/detect", "/api/config"} {
		resp, _ := doReq(t, anon, "GET", base+ep, "", "", nil)
		if resp.StatusCode != 401 {
			t.Fatalf("unauthenticated GET %s must be 401, got %d", ep, resp.StatusCode)
		}
	}
}
