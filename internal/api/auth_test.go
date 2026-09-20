package api

import "testing"

func TestAllowedOriginNoPortDoesNotPanic(t *testing.T) {
	// Regression: a scheme-ful Origin without a port previously sliced
	// host[0:-1] and panicked the server.
	if allowedOrigin("http://blocked") {
		t.Fatal("non-local origin with no port must be rejected, not accepted")
	}
	if allowedOrigin("https://notlocalhost") {
		t.Fatal("non-local origin must be rejected")
	}
}

func TestAllowedOriginPrivateSubnets(t *testing.T) {
	// localhost / loopback
	for _, o := range []string{"http://localhost:8080", "http://127.0.0.1:8443", "http://[::1]:8443"} {
		if !allowedOrigin(o) {
			t.Fatalf("origin %q should be allowed", o)
		}
	}
	// full RFC1918 172.16.0.0/12 (172.16-172.31), including 172.20 (BUG-006).
	if !allowedOrigin("http://172.16.5.5:8080") {
		t.Fatal("172.16 should be allowed")
	}
	if !allowedOrigin("http://172.20.1.1:8080") {
		t.Fatal("172.20 should be allowed (full /12 range)")
	}
	if !allowedOrigin("http://192.168.1.10:80") {
		t.Fatal("192.168 should be allowed")
	}
	if !allowedOrigin("http://10.0.0.5:80") {
		t.Fatal("10.0.0.0/8 should be allowed")
	}
	// non-private, non-loopback
	if allowedOrigin("http://8.8.8.8:80") {
		t.Fatal("public IP origin must be rejected")
	}
}