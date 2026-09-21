package gateway

import (
	"encoding/binary"
	"math/rand"
	"strings"
	"sync/atomic"
	"time"

	"gfw-x/internal/detect"
)

// Generator simulates a packet source so the gateway can be evaluated and the
// dashboard populated without touching real network interfaces. It produces
// realistic handshake samples (TLS ClientHello / DNS / WireGuard).
type Generator struct {
	g       *Gateway
	rate    atomic.Int64 // events per second
	stopCh  chan struct{}
	corpus  []string
	blocked []string
	rng     *rand.Rand
}

// NewGenerator builds a generator over a gateway.
func NewGenerator(g *Gateway, ratePerSec int) *Generator {
	gen := &Generator{
		g:      g,
		rate:   atomic.Int64{},
		stopCh: make(chan struct{}),
		corpus: []string{
			"github.com", "api.github.com", "huggingface.co", "cdn-lfs.huggingface.co",
			"api.openai.com", "claude.ai", "api.anthropic.com", "pages.dev",
			"api.pages.dev", "cdn.jsdelivr.net", "registry.npmjs.org", "gstatic.com",
			"googletagmanager.com", "x.com", "api.x.com", "weixin.qq.com",
			"q.qq.com", "www.douyin.com", "update.microsoft.com", "apple.com",
		},
		blocked: []string{
			"example-adult.com", "stream-adult-x.com", "gamblecasino.net",
			"badpoker.io", "phish-zone.net", "malware-host.example",
		},
		rng: rand.New(rand.NewSource(0x5EED)),
	}
	gen.SetRate(ratePerSec)
	return gen
}

// SetRate changes events/sec.
func (g *Generator) SetRate(perSec int) {
	if perSec < 1 {
		perSec = 1
	}
	g.rate.Store(int64(perSec))
}

// Start begins emitting traffic.
func (g *Generator) Start() {
	go g.loop()
}

// Stop halts the generator.
func (g *Generator) Stop() {
	select {
	case <-g.stopCh:
	default:
		close(g.stopCh)
	}
}

func (g *Generator) loop() {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	rateF := 0.0
	for {
		select {
		case <-g.stopCh:
			return
		case <-tick.C:
			rateF = rateF*0.9 + float64(g.rate.Load())*0.1
			frames := int(rateF * 0.05) // events per 50ms tick
			if frames < 1 {
				frames = 1
			}
			for i := 0; i < frames; i++ {
				g.emitOne()
			}
		}
	}
}

func (g *Generator) emitOne() {
	r := g.rng
	src := randClientIP(r)
	// Mostly known-good TLS; a mix of DNS and tunnel/suspicious traffic.
	switch r.Intn(10) {
	case 0, 1:
		// DNS queries
		domain := g.corpus[r.Intn(len(g.corpus))]
		if r.Intn(6) == 0 {
			domain = g.blocked[r.Intn(len(g.blocked))]
		}
		g.g.Ingest(&Traffic{
			SrcIP: src, DstIP: randServerIP(r),
			SrcPort: uint16(40000 + r.Intn(20000)), DstPort: 53, Transport: "udp",
			Sample: buildDNSQuery(domain), Category: classifyDomain(domain),
			UpBytes: 80, DownBytes: 300, UpPkts: 1, DownPkts: 3, LifetimeSec: 0.1,
		})
	case 2:
		// WireGuard tunnel (suspicious, slow path)
		g.g.Ingest(&Traffic{
			SrcIP: src, DstIP: randServerIP(r),
			SrcPort: uint16(40000 + r.Intn(20000)), DstPort: 51820, Transport: "udp",
			Sample: buildWireGuard(), Category: "vpn-tunnel",
			UpBytes: 1200, DownBytes: 4000, UpPkts: 4, DownPkts: 9,
			Features: &detect.Features{
				UpDownRatio: 0.5, Alternation: 0.8, Keepalive: 30,
				BurstInterval: 2.5, Lifetime: 600, Handshake: 0.1,
				MinPkt: 96, MaxPkt: 1420,
			},
			LifetimeSec: 300,
		})
	default:
		// TLS ClientHello sessions
		domain := g.corpus[r.Intn(len(g.corpus))]
		if r.Intn(7) == 0 {
			domain = g.blocked[r.Intn(len(g.blocked))]
		}
		g.g.Ingest(&Traffic{
			SrcIP: src, DstIP: randServerIP(r),
			SrcPort: uint16(40000 + r.Intn(20000)), DstPort: 443, Transport: "tcp",
			Sample: buildClientHello(domain), Category: classifyDomain(domain),
			UpBytes: uint64(400 + r.Intn(2000)), DownBytes: uint64(4000 + r.Intn(120000)),
			UpPkts: 2, DownPkts: 8, LifetimeSec: float64(r.Intn(60) + 2),
		})
	}
}

func classifyDomain(d string) string {
	switch d {
	case "gamblecasino.net", "badpoker.io":
		return "gambling"
	case "example-adult.com", "stream-adult-x.com":
		return "adult"
	case "phish-zone.net", "malware-host.example":
		return "malicious"
	case "vpn-tunnel":
		return "vpn-tunnel"
	}
	return ""
}

// buildClientHello encodes a minimal TLS 1.2/1.3 ClientHello carrying SNI.
func buildClientHello(domain string) []byte {
	sni := []byte(domain)
	// extension: server_name (0x0000), len, list_len(2), name_type(1), len(2)...
	var name bytesBuffer
	put16(&name, 0) // name_type: host_name
	put16(&name, uint16(len(sni)))
	name.Write(sni)
	listLen := len(name.B)
	var serverNameExt bytesBuffer
	put16(&serverNameExt, uint16(listLen))
	serverNameExt.Write(name.B)
	// final extension body
	var extBody bytesBuffer
	extBody.Write(serverNameExt.B)

	// build handshake: ClientHello
	var hello bytesBuffer
	put16(&hello, 0x0303) // client_version TLS1.2
	for i := 0; i < 32; i++ {
		hello.WriteByte(byte(i))
	} // random
	hello.WriteByte(0) // session id length
	put16(&hello, 0x0002)
	hello.Write([]byte{0x00, 0x2f}) // cipher suites TLS_RSA
	hello.WriteByte(1)
	hello.WriteByte(0) // compression
	put16(&hello, uint16(len(extBody.B)))
	hello.Write(extBody.B) // extensions

	body := hello.B
	// handshake record: type ClientHello 0x01, 3-byte length
	var hs bytesBuffer
	hs.WriteByte(0x01)
	hs.Write([]byte{byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))})
	hs.Write(body)

	rec := hs.B
	out := []byte{0x16, 0x03, 0x01, byte(len(rec) >> 8), byte(len(rec))}
	out = append(out, rec...)
	return out
}

type bytesBuffer struct{ B []byte }

func (b *bytesBuffer) Write(p []byte)         { b.B = append(b.B, p...) }
func (b *bytesBuffer) WriteByte(c byte) error { b.B = append(b.B, c); return nil }

func put16(b *bytesBuffer, v uint16) {
	b.B = append(b.B, byte(v>>8), byte(v))
}

func buildDNSQuery(domain string) []byte {
	out := make([]byte, 0, 64)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], 0x1234) // id
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // flags: rd
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // qdcount
	hdr[5] = 0
	out = append(out, hdr...)
	for _, label := range strings.Split(domain, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)    // root
	out = append(out, 0, 1) // A
	out = append(out, 0, 1) // IN
	return out
}

func buildWireGuard() []byte {
	b := make([]byte, 32)
	b[0] = 0x01 // WireGuard message type
	// reserved bytes zero
	return b
}

func randClientIP(r *rand.Rand) string {
	return "192.168." + itoaU(int(r.Intn(255))) + "." + itoaU(int(r.Intn(254)+1))
}

func randServerIP(r *rand.Rand) string {
	return "35." + itoaU(int(r.Intn(255))) + "." + itoaU(int(r.Intn(255))) + "." + itoaU(int(r.Intn(254)+1))
}

func itoaU(v int) string {
	if v == 0 {
		return "0"
	}
	var b [3]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
