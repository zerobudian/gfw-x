package integration

import (
	"bytes"
	"testing"
	"time"

	"gfw-x/internal/config"
	"gfw-x/internal/gateway"
	"gfw-x/internal/metrics"
)

// feedTLS ingests a TCP/443 flow on a fresh 5-tuple and waits for the blocked
// counter to reach before+delta. Serial src-port prevents cache collisions.
func feedTLS(t *testing.T, gw *gateway.Gateway, m *metrics.Registry, seq int, srcIP, dstIP string, sample []byte, delta int64) int64 {
	t.Helper()
	before := m.C.Blocked.Load()
	gw.Ingest(&gateway.Traffic{
		SrcIP: srcIP, DstIP: dstIP,
		SrcPort: uint16(40000+seq%6000), DstPort: 443,
		Transport: "tcp", Sample: sample,
		UpBytes: 256, DownBytes: 4096,
	})
	waitFor(t, 3*time.Second, func() bool {
		return m.C.Blocked.Load() == before+delta
	}, "tls decision")
	return before
}

func TestTLSIntegration_TLS12SNI_Blocked(t *testing.T) {
	gw, m, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
	defer cleanup()
	feedTLS(t, gw, m, 1, "10.0.0.10", "93.184.216.34", clientHello(0x0303, "example.com", true), 1)
}

func TestTLSIntegration_TLS13SNI_Blocked(t *testing.T) {
	gw, m, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
	defer cleanup()
	feedTLS(t, gw, m, 2, "10.0.0.11", "93.184.216.34", clientHello(0x0304, "example.com", true), 1)
}

// No SNI must NEVER result in an automatic block, even on port 443 and even
// when the rule would match the (unknown) host.
func TestTLSIntegration_NoSNI_NotBlocked(t *testing.T) {
	gw, m, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
	defer cleanup()
	before := m.C.Blocked.Load()
	gw.Ingest(&gateway.Traffic{
		SrcIP: "10.0.0.12", DstIP: "93.184.216.34",
		SrcPort: 40002, DstPort: 443,
		Transport: "tcp", Sample: clientHello(0x0303, "", false),
		UpBytes: 256, DownBytes: 4096,
	})
	time.Sleep(120 * time.Millisecond)
	if m.C.Blocked.Load() != before {
		t.Fatalf("TLS without SNI must never auto-block, blocked=%d", m.C.Blocked.Load())
	}
	if m.C.Observed.Load() == 0 {
		t.Fatal("no-SNI TLS should route to observe")
	}
}

// Non-TLS bytes on TCP/443 (e.g. raw HTTP) must not be treated as TLS and must
// not be blocked from a bogus SNI extraction.
func TestTLSIntegration_TCP443NonTLS_NotBlocked(t *testing.T) {
	gw, m, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
	defer cleanup()
	before := m.C.Blocked.Load()
	gw.Ingest(&gateway.Traffic{
		SrcIP: "10.0.0.13", DstIP: "93.184.216.34",
		SrcPort: 40003, DstPort: 443,
		Transport: "tcp", Sample: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		UpBytes: 256, DownBytes: 4096,
	})
	time.Sleep(120 * time.Millisecond)
	if m.C.Blocked.Load() != before {
		t.Fatal("non-TLS TCP/443 must not be blocked via SNI")
	}
}

// Fragmented ClientHello: only the first part of the record is observed. The
// parser must not panic and, lacking a complete SNI, must not block.
func TestTLSIntegration_FragmentedHello_NoPanic(t *testing.T) {
	gw, m, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
	defer cleanup()
	full := clientHello(0x0303, "example.com", true)
	half := full[:len(full)/2]
	before := m.C.Blocked.Load()
	gw.Ingest(&gateway.Traffic{
		SrcIP: "10.0.0.14", DstIP: "93.184.216.34",
		SrcPort: 40004, DstPort: 443,
		Transport: "tcp", Sample: half,
		UpBytes: 128, DownBytes: 100,
	})
	time.Sleep(120 * time.Millisecond)
	if m.C.Blocked.Load() != before {
		t.Fatal("fragmented hello must not be blocked")
	}
}

// Malformed extension length (extTotal claims more than the record holds).
// Must not panic; SNI is absent -> observe.
func TestTLSIntegration_MalformedExtension_NoPanic(t *testing.T) {
	gw, m, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
	defer cleanup()
	full := clientHello(0x0303, "example.com", true)
	// Corrupt the extension total length to an absurd value. Find the
	// ext_total field: handshake type(1)+len(3)+ver(2)+random(32)+sid(1)+
	// ciphers(len2+2)+comp(len1+1) all before extTotal. We just poke a byte in
	// the extension area to force a malformed length and rely on no-panic.
	bad := bytes.Clone(full)
	if len(bad) > 70 {
		bad[70] = 0x7f
	}
	before := m.C.Blocked.Load()
	gw.Ingest(&gateway.Traffic{
		SrcIP: "10.0.0.15", DstIP: "93.184.216.34",
		SrcPort: 40005, DstPort: 443,
		Transport: "tcp", Sample: bad,
		UpBytes: 256, DownBytes: 400,
	})
	time.Sleep(120 * time.Millisecond)
	if m.C.Blocked.Load() != before {
		t.Fatal("malformed extension must not be blocked (SNI likely unreadable)")
	}
}

// A different SNI must not match BLOCK example.com.
func TestTLSIntegration_OtherSNINotBlocked(t *testing.T) {
	gw, m, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
	defer cleanup()
	before := m.C.Blocked.Load()
	gw.Ingest(&gateway.Traffic{
		SrcIP: "10.0.0.16", DstIP: "1.1.1.1",
		SrcPort: 40006, DstPort: 443,
		Transport: "tcp", Sample: clientHello(0x0303, "cloudflare.com", true),
		UpBytes: 256, DownBytes: 4096,
	})
	time.Sleep(120 * time.Millisecond)
	if m.C.Blocked.Load() != before {
		t.Fatal("non-matching SNI must not be blocked")
	}
	if m.C.Observed.Load() == 0 {
		t.Fatal("non-matching SNI should be observed")
	}
}