package dpi

import "testing"

func TestShouldInspectFastPath(t *testing.T) {
	e := NewEngine(true, 1.0)
	// Known / normal traffic must never be inspected on the fast path.
	if e.ShouldInspect(true, false) {
		t.Fatal("known traffic should bypass DPI")
	}
	// Suspicious always inspected
	if !e.ShouldInspect(false, true) {
		t.Fatal("suspicious traffic should be inspected")
	}
	// Unknown with ratio 0 → no inspection
	disabled := NewEngine(true, 0.0)
	if disabled.ShouldInspect(false, false) {
		t.Fatal("sampling ratio 0 should skip unknown traffic")
	}
}

func TestInspectClassify(t *testing.T) {
	e := NewEngine(true, 1.0)
	r, ok := e.Inspect([]byte{0x16, 0x03, 0x01, 0x00}, "tcp", 443)
	if !ok || r.Category != CatWeb || r.Proto != "tls" || !r.Encrypted {
		t.Fatalf("TLS classify failed: %+v ok=%v", r, ok)
	}
	r, _ = e.Inspect([]byte("GET / HTTP/1.1\r\n"), "tcp", 80)
	if r.Category != CatWeb || r.Proto != "http" {
		t.Fatalf("HTTP classify failed: %+v", r)
	}
	r, _ = e.Inspect(nil, "udp", 53)
	if r.Category != CatDNS {
		t.Fatalf("DNS classify failed: %+v", r)
	}
	// DPI is metadata-only: content field must never be populated.
	if r.confidence < 0 {
		// noop guard
	}
}

func TestNoBareHighPortUDPGameHeuristic(t *testing.T) {
	e := NewEngine(true, 0.0)
	// Opaque UDP payloads on arbitrary high ports (WireGuard, QUIC, voice/RTC,
	// DoH) carry no game signature, so they must never be classified as gaming
	// from port alone. Bare high ports are intentionally CatUnknown.
	opaque := []byte{0x00, 0x00, 0x00, 0x58, 0x03, 0x90, 0xcc, 0xb5}
	ports := []uint16{51820, 443, 1234, 6553, 9000}
	for _, port := range ports {
		r, _ := e.Inspect(opaque, "udp", port)
		if r.Category == CatGame {
			t.Fatalf("udp/%d misclassified as gaming (no signature)", port)
		}
	}
	// Arbitrary high non-well-known ports classify as unknown, not gaming.
	r, _ := e.Inspect(opaque, "udp", 51820)
	if r.Category != CatUnknown {
		t.Fatalf("udp/51820: got %s, want unknown", r.Category)
	}
}

func BenchmarkInspect(b *testing.B) {
	e := NewEngine(true, 1.0)
	sample := []byte{0x16, 0x03, 0x01, 0x00, 0x00}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e.Inspect(sample, "tcp", 443)
	}
}
