package integration

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"gfw-x/internal/api"
	"gfw-x/internal/config"
	"gfw-x/internal/detect"
	"gfw-x/internal/dpi"
	"gfw-x/internal/gateway"
	"gfw-x/internal/logging"
	"gfw-x/internal/metrics"
	"gfw-x/internal/rules"
)

// newConfig returns a deterministic, in-memory-friendly config.
// Detection and DPI are disabled so decisions are purely rule+mode driven.
func newConfig(mode config.Mode) *config.Config {
	cfg := config.DefaultConfig()
	cfg.Default.Mode = mode
	cfg.Default.DPI = 0 // no DPI re-classification in decision tests
	cfg.Detect.Enabled = false
	cfg.Runtime.WorkerPool = 2
	cfg.Runtime.ChannelCapacity = 4096
	cfg.Runtime.FlowTTL = 30
	cfg.Logging.Format = "ring"
	cfg.Logging.MaxRing = 8192
	cfg.Logging.Redact = false
	cfg.Logging.SampleRatio = 1.0
	cfg.Server.Listen = "127.0.0.1:0"
	return cfg
}

// mustRepo parses rule lines into a fresh repo.
func mustRepo(t *testing.T, lines string) *rules.RuleRepo {
	t.Helper()
	rs, err := rules.ParseBytes([]byte(lines), "txt")
	if err != nil {
		t.Fatalf("parse rules: %v", err)
	}
	repo := rules.NewRepo()
	repo.Replace(rs)
	return repo
}

// mustParse returns the parsed rule slice (used for import/export tests).
func mustParse(t *testing.T, data, src string) []*rules.Rule {
	t.Helper()
	rs, err := rules.ParseBytes([]byte(data), src)
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}
	return rs
}

// newGateway builds a running gateway over an in-memory ring logger.
// Returns the gateway, metrics, and a cleanup func.
func newGateway(t *testing.T, mode config.Mode, rulesText string) (*gateway.Gateway, *metrics.Registry, func()) {
	t.Helper()
	cfg := newConfig(mode)
	repo := mustRepo(t, rulesText)
	m := metrics.New(8192)
	pipe := logging.NewPipeline(logging.RingStorage{}, 4096, true, 1.0)
	det := detect.NewEngine(false, 0.85, false)
	dpiEng := dpi.NewEngine(true, 0.0)
	gw := gateway.New(cfg, repo, m, pipe, det, dpiEng)
	gw.Start()
	return gw, m, func() {
		gw.Stop()
		time.Sleep(20 * time.Millisecond) // allow workers to drain
		_ = pipe.Close()
	}
}

// waitFor polls cond until true or timeout.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", msg)
}

// --- DNS packet builders ---

// dnsQuery builds a real DNS query packet for the given name/qtype.
func dnsQuery(name string, qtype uint16) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint16(0xbeef)) // id
	_ = binary.Write(&b, binary.BigEndian, uint16(0x0100)) // RD
	_ = binary.Write(&b, binary.BigEndian, uint16(1))      // qdcount
	_ = binary.Write(&b, binary.BigEndian, uint16(0))      // ancount
	_ = binary.Write(&b, binary.BigEndian, uint16(0))      // nscount
	_ = binary.Write(&b, binary.BigEndian, uint16(0))      // arcount
	for _, label := range strings.Split(name, ".") {
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	_ = binary.Write(&b, binary.BigEndian, qtype)
	_ = binary.Write(&b, binary.BigEndian, uint16(1)) // class IN
	return b.Bytes()
}

// dnsResponse builds a real DNS response packet (QR bit set) with the given
// number of answer records, so the gateway's query parser must reject it
// without panicking.
func dnsResponse(name string, answers int) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.BigEndian, uint16(0xbeef)) // id
	_ = binary.Write(&b, binary.BigEndian, uint16(0x8180)) // QR=1 RD RA
	_ = binary.Write(&b, binary.BigEndian, uint16(1))      // qdcount
	_ = binary.Write(&b, binary.BigEndian, uint16(answers))
	_ = binary.Write(&b, binary.BigEndian, uint16(0)) // nscount
	_ = binary.Write(&b, binary.BigEndian, uint16(0)) // arcount
	for _, label := range strings.Split(name, ".") {
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	_ = binary.Write(&b, binary.BigEndian, uint16(1)) // A
	_ = binary.Write(&b, binary.BigEndian, uint16(1)) // IN
	for i := 0; i < answers; i++ {
		_ = binary.Write(&b, binary.BigEndian, uint16(0xc00c)) // ptr to offset 12
		_ = binary.Write(&b, binary.BigEndian, uint16(1))      // A
		_ = binary.Write(&b, binary.BigEndian, uint16(1))      // IN
		_ = binary.Write(&b, binary.BigEndian, uint32(300))
		_ = binary.Write(&b, binary.BigEndian, uint16(4))
		b.Write([]byte{1, 2, 3, byte(4 + i)})
	}
	return b.Bytes()
}

// dnsTruncatedQuery returns a valid query truncated mid-question-section.
func dnsTruncatedQuery(name string) []byte {
	return dnsQuery(name, 1)[:15]
}

// --- TLS ClientHello builder ---

// clientHello builds a real TLS ClientHello record. When includeSNI is true an
// SNI extension names the given host.
func clientHello(version uint16, sni string, includeSNI bool) []byte {
	var ext []byte
	if includeSNI {
		var se bytes.Buffer
		se.WriteByte(0) // name type: host_name (1 byte)
		_ = binary.Write(&se, binary.BigEndian, uint16(len(sni)))
		se.WriteString(sni)
		var nl bytes.Buffer
		_ = binary.Write(&nl, binary.BigEndian, uint16(se.Len()))
		nl.Write(se.Bytes())
		var ee bytes.Buffer
		_ = binary.Write(&ee, binary.BigEndian, uint16(0)) // ext type: server_name
		_ = binary.Write(&ee, binary.BigEndian, uint16(nl.Len()))
		ee.Write(nl.Bytes())
		ext = ee.Bytes()
	}
	var body bytes.Buffer
	_ = binary.Write(&body, binary.BigEndian, version) // client_version
	body.Write(make([]byte, 32))                       // random
	body.WriteByte(0)                                  // session id length
	_ = binary.Write(&body, binary.BigEndian, uint16(2))
	_ = binary.Write(&body, binary.BigEndian, uint16(0x1301)) // cipher suite
	body.WriteByte(1)
	body.WriteByte(0) // no compression
	_ = binary.Write(&body, binary.BigEndian, uint16(len(ext)))
	body.Write(ext)

	var hs bytes.Buffer
	hs.WriteByte(0x01) // ClientHello
	hlen := body.Len()
	hs.WriteByte(byte(hlen >> 16))
	hs.WriteByte(byte(hlen >> 8))
	hs.WriteByte(byte(hlen))
	hs.Write(body.Bytes())

	var rec bytes.Buffer
	rec.WriteByte(0x16) // handshake
	rec.WriteByte(0x03)
	rec.WriteByte(0x01)
	_ = binary.Write(&rec, binary.BigEndian, uint16(hs.Len()))
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

// --- API server harness ---

// startAPI brings up the real HTTP server on an ephemeral loopback port.
func startAPI(t *testing.T, gw *gateway.Gateway, cfg *config.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	cfg.Server.Listen = fmt.Sprintf("127.0.0.1:%d", port)
	srv := api.New(gw, cfg)
	go func() { _ = srv.Listen() }()
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 3 * time.Second}
	waitFor(t, 5*time.Second, func() bool {
		resp, err := client.Get(base + "/api/health")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == 200
	}, "api server ready")
	return base
}

// doReq performs an HTTP request.
func doReq(t *testing.T, client *http.Client, method, url, body string, csrf string, headers map[string]string) (*http.Response, string) {
	t.Helper()
	var bodyR io.Reader
	if body != "" {
		bodyR = bytes.NewReader([]byte(body))
	}
	req, err := http.NewRequest(method, url, bodyR)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, url, err)
	}
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	resp.Body.Close()
	return resp, buf.String()
}

// login performs a valid login and returns a cookie-bearing client + CSRF token.
func login(t *testing.T, base string) (*http.Client, string) {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("jar: %v", err)
	}
	client := &http.Client{Timeout: 3 * time.Second, Jar: jar}
	resp, body := doReq(t, client, "POST", base+"/api/login", `{"username":"admin","password":"admin"}`, "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("login failed: %d %s", resp.StatusCode, body)
	}
	var out struct {
		OK   string `json:"ok"`
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	return client, out.CSRF
}

// mode reads the current mode from /api/status.
func modeFromStatus(t *testing.T, client *http.Client, base, csrf string) string {
	t.Helper()
	resp, body := doReq(t, client, "GET", base+"/api/status", "", csrf, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status: %d %s", resp.StatusCode, body)
	}
	var out struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	return out.Mode
}