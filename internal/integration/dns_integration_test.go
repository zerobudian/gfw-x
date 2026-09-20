package integration

import (
	"testing"
	"time"

	"gfw-x/internal/config"
	"gfw-x/internal/gateway"
	"gfw-x/internal/metrics"
)

// feedDNS ingests a DNS packet on UDP/53 as a fresh flow and waits for the
// gateway's blocked counter to change by d. Returns the prior count.
func feedDNS(t *testing.T, gw *gateway.Gateway, m *metrics.Registry, srcIP, dstIP string, pkt []byte, d int64) int64 {
	t.Helper()
	before := m.C.Blocked.Load()
	gw.Ingest(&gateway.Traffic{
		SrcIP: srcIP, DstIP: dstIP,
		SrcPort: 53421, DstPort: 53,
		Transport: "udp", Sample: pkt,
		UpBytes: 512, DownBytes: 512,
	})
	want := before + d
	waitFor(t, 3*time.Second, func() bool {
		return m.C.Blocked.Load() == want
	}, "dns decision")
	return before
}

func TestDNSIntegrationQueryA_Blocked(t *testing.T) {
	gw, m, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
	defer cleanup()
	feedDNS(t, gw, m, "10.0.0.2", "8.8.8.8", dnsQuery("example.com", 1), 1)
}

func TestDNSIntegrationQueryAAAA_Blocked(t *testing.T) {
	gw, m, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
	defer cleanup()
	// AAAA query over IPv6 endpoints.
	feedDNS(t, gw, m, "2001:db8::1", "2001:4860:4860::8888", dnsQuery("example.com", 28), 1)
}

func TestDNSIntegrationQueryCNAME_Blocked(t *testing.T) {
	gw, m, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
	defer cleanup()
	feedDNS(t, gw, m, "10.0.0.3", "8.8.8.8", dnsQuery("example.com", 5), 1)
}

// Response packets (NXDOMAIN, multiple answers) carry QR=1; the gateway's query
// parser must reject them without extracting a domain and without panicking,
// so the flow is unknown -> observe, never block, even though the name matches.
func TestDNSIntegrationResponse_NeverBlocked(t *testing.T) {
	for _, name := range []struct {
		label string
		pkt   func() []byte
	}{
		{"nxdomain", func() []byte { return dnsResponse("example.com", 0) }},
		{"multi_answers", func() []byte { return dnsResponse("example.com", 3) }},
	} {
		t.Run(name.label, func(t *testing.T) {
			gw, m, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
			defer cleanup()
			before := m.C.Blocked.Load()
			gw.Ingest(&gateway.Traffic{
				SrcIP: "10.0.0.4", DstIP: "8.8.8.8",
				SrcPort: 53422, DstPort: 53,
				Transport: "udp", Sample: name.pkt(),
				UpBytes: 512, DownBytes: 512,
			})
			time.Sleep(100 * time.Millisecond)
			if got := m.C.Blocked.Load(); got != before {
				t.Fatalf("DNS response must not be blocked (no domain extracted), blocked=%d before=%d", got, before)
			}
			// It should have been observed, not rejected.
			if m.C.Observed.Load() == 0 {
				t.Fatal("DNS response should be routed to observe, got no observed counts")
			}
		})
	}
}

// Malformed and truncated bytes on UDP/53 must never panic and must never be
// classified as a known domain (no block).
func TestDNSIntegrationMalformed_NeverPanics(t *testing.T) {
	cases := []struct {
		label string
		pkt   []byte
	}{
		{"short_header", []byte{0x00}},
		{"garbage", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
		{"truncated_query", dnsTruncatedQuery("example.com")},
		{"mid_label", append([]byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0x3f, 0x03)},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			gw, m, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
			defer cleanup()
			before := m.C.Blocked.Load()
			gw.Ingest(&gateway.Traffic{
				SrcIP: "10.0.0.5", DstIP: "8.8.8.8",
				SrcPort: 53423, DstPort: 53,
				Transport: "udp", Sample: c.pkt,
				UpBytes: 512, DownBytes: 512,
			})
			time.Sleep(100 * time.Millisecond)
			if got := m.C.Blocked.Load(); got != before {
				t.Fatalf("malformed dns must not be blocked, blocked=%d", got)
			}
		})
	}
}

// Suffix rule: DNS query for a subdomain must match *.example.com by domain.
func TestDNSIntegrationSuffixRuleMatch(t *testing.T) {
	gw, m, cleanup := newGateway(t, config.ModeBlock, "BLOCK *.example.com\n")
	defer cleanup()
	feedDNS(t, gw, m, "10.0.0.6", "8.8.8.8", dnsQuery("www.example.com", 1), 1)
}

// A non-blocked domain under block mode is observed, not blocked.
func TestDNSIntegrationAllowedDomainNotBlocked(t *testing.T) {
	gw, m, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
	defer cleanup()
	before := m.C.Blocked.Load()
	gw.Ingest(&gateway.Traffic{
		SrcIP: "10.0.0.7", DstIP: "8.8.8.8",
		SrcPort: 53424, DstPort: 53,
		Transport: "udp", Sample: dnsQuery("google.com", 1),
		UpBytes: 512, DownBytes: 512,
	})
	time.Sleep(100 * time.Millisecond)
	if m.C.Blocked.Load() != before {
		t.Fatal("unrelated domain must not be blocked")
	}
	if m.C.Observed.Load() == 0 {
		t.Fatal("unrelated domain should be observed")
	}
}