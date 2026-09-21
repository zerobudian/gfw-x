// Package lab is a PCAP regression harness for the gateway. It generates
// small deterministic classic .pcap fixtures, replays them through a real
// gateway, and reports how they were classified. It is fully hermetic: it
// needs no root, no network, and only uses the fixtures it creates under
// ../testdata.
package lab

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"gfw-x/internal/config"
	"gfw-x/internal/detect"
	"gfw-x/internal/dpi"
	"gfw-x/internal/gateway"
	"gfw-x/internal/logging"
	"gfw-x/internal/metrics"
	"gfw-x/internal/rules"
)

// Expected is the ground-truth spec for one fixture, mirroring the JSON files
// under testdata/expected.
type Expected struct {
	Protocol       string  `json:"protocol"`
	Category       string  `json:"category"`
	ExpectedAction string  `json:"expected_action"`
	ConfidenceMin  float64 `json:"confidence_min"`
	Note           string  `json:"note"`
}

// caseResult is the evaluated outcome of one fixture.
type caseResult struct {
	CaseName   string
	Expected   Expected
	Events     []*metrics.Event
	Proto      string
	Category   string
	Action     string
	Confidence float64
	Pass       bool
	Mismatch   string
}

// --- pcap fixture generation ---------------------------------------------

// dnsPayload builds a minimal DNS query for example.com: header id 0x1234,
// flags 0x0100, QDCOUNT=1, then qname example.com, qtype A, qclass IN.
func dnsPayload() []byte {
	name := []byte{
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
	}
	body := []byte{
		0x12, 0x34, // ID 0x1234
		0x01, 0x00, // flags: RD
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	}
	body = append(body, name...)
	body = append(body, 0x00, 0x01, 0x00, 0x01) // qtype A, qclass IN
	return body
}

// buildClientHello builds a minimal TLS ClientHello record carrying an SNI for
// "github.com", shaped exactly the way the gateway's tls parser expects.
func buildClientHello() []byte {
	name := []byte("github.com")

	// server_name extension body: list_len + name_type + name_len + name.
	extBody := make([]byte, 0, 32)
	extBody = append(extBody, byte((1+2+len(name))>>8), byte(1+2+len(name))) // list len
	extBody = append(extBody, 0x00)                                          // name_type = host_name
	extBody = append(extBody, byte(len(name)>>8), byte(len(name)))           // name len
	extBody = append(extBody, name...)                                       // name "github.com"

	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i + 1)
	}

	// Handshake body: version + random + session_id + cipher suites + comp + ext.
	body := make([]byte, 0, 96)
	body = append(body, 0x03, 0x03) // legacy_version 0x0303
	body = append(body, random...)
	body = append(body, 0x00) // session id length = 0
	body = append(body, 0x00, 0x02)
	body = append(body, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00) // compression methods len=1, null
	// extensions: type(2)+len(2)+extBody
	body = append(body, byte((4+len(extBody))>>8), byte(4+len(extBody)))
	body = append(body, 0x00, 0x00) // server_name ext type
	body = append(body, byte(len(extBody)>>8), byte(len(extBody)))
	body = append(body, extBody...)

	// Handshake message: type(1) + length(3) + body.
	hs := make([]byte, 0, 4+len(body))
	hs = append(hs, 0x01) // ClientHello
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	// TLS record: type(1) 0x16, version(2) 0x0301, length(2).
	rec := make([]byte, 0, 5+len(hs))
	rec = append(rec, 0x16, 0x03, 0x01)
	rec = append(rec, byte(len(hs)>>8), byte(len(hs)))
	rec = append(rec, hs...)
	return rec
}

func mustIP(s string) net.IP { return net.ParseIP(s) }

// tcpFrame builds an Ethernet/IPv4/TCP frame carrying payload.
func tcpFrame(sport, dport uint16, src, dst string, payload []byte) []byte {
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
		SrcIP: mustIP(src), DstIP: mustIP(dst)}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport),
		Seq: 1, SYN: true, Window: 65535}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	b := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(b, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		panic(err)
	}
	return b.Bytes()
}

// udpFrame builds an Ethernet/IPv4/UDP frame carrying payload.
func udpFrame(sport, dport uint16, src, dst string, payload []byte) []byte {
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: mustIP(src), DstIP: mustIP(dst)}
	udp := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
	_ = udp.SetNetworkLayerForChecksum(ip)
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	b := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(b, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		panic(err)
	}
	return b.Bytes()
}

func writePCAP(path string, pkts [][]byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return err
	}
	ts := time.Unix(1700000000, 0)
	for i := range pkts {
		ci := gopacket.CaptureInfo{
			Timestamp:     ts.Add(time.Duration(i) * time.Second),
			CaptureLength: len(pkts[i]),
			Length:        len(pkts[i]),
		}
		if err := w.WritePacket(ci, pkts[i]); err != nil {
			return err
		}
	}
	return f.Sync()
}

// GenerateFixtures writes the deterministic .pcap fixtures under dataDir/pcaps.
// It is idempotent and safe to call from a test.
func GenerateFixtures(dataDir string) error {
	pcaps := filepath.Join(dataDir, "pcaps")
	if err := os.MkdirAll(pcaps, 0o755); err != nil {
		return err
	}
	if err := writePCAP(filepath.Join(pcaps, "dns_query.pcap"), [][]byte{
		udpFrame(54321, 53, "10.0.0.5", "192.0.2.1", dnsPayload()),
	}); err != nil {
		return err
	}
	if err := writePCAP(filepath.Join(pcaps, "tls_sni.pcap"), [][]byte{
		tcpFrame(49152, 443, "10.0.0.5", "192.0.2.10", buildClientHello()),
	}); err != nil {
		return err
	}
	return nil
}

// --- gateway replay harness ----------------------------------------------

// buildGateway wires a fresh gateway over the deterministic minimal rule set so
// that every fixture is decided as OBSERVE (no blocking rules for our domains).
func buildGateway() (*gateway.Gateway, *logging.Pipeline, error) {
	cfg := config.DefaultConfig()
	cfg.Runtime.WorkerPool = 2
	cfg.Runtime.ChannelCapacity = 1024
	cfg.Runtime.FlowTTL = 30

	// Deterministic minimal set: OBSERVE both target domains -> observe.
	rs, err := rules.ParseBytes([]byte(
		"OBSERVE example.com\nOBSERVE github.com\n"), "lab")
	if err != nil {
		return nil, nil, err
	}
	repo := rules.NewRepo()
	repo.Replace(rs)

	// Sanity-check that the built-in preset API is reachable (developer preset
	// are the repo's default rules; we intentionally override with our own
	// minimal set so expected_action is deterministic).
	if _, ok := rules.PresetBy("developer"); !ok {
		return nil, nil, errors.New("rules.PresetBy(\"developer\") unavailable")
	}

	m := metrics.New(1024)
	lg := logging.NewPipeline(logging.RingStorage{}, 1024, true, 1.0)
	det := detect.NewEngine(true, 0.85, false)
	dp := dpi.NewEngine(true, 0.02)
	g := gateway.New(cfg, repo, m, lg, det, dp)
	g.Start()
	return g, lg, nil
}

func loadExpected(dataDir, name string) (Expected, error) {
	var exp Expected
	f, err := os.Open(filepath.Join(dataDir, "expected", name+".json"))
	if err != nil {
		return exp, err
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&exp); err != nil {
		return exp, err
	}
	return exp, nil
}

func waitForEvents(m *metrics.Registry, want int, timeout time.Duration) []*metrics.Event {
	deadline := time.Now().Add(timeout)
	last := -1
	lastStable := time.Now()
	for time.Now().Before(deadline) {
		evs := m.Events()
		if n := len(evs); n != last {
			last = n
			lastStable = time.Now()
		}
		if last >= want && time.Since(lastStable) > 50*time.Millisecond {
			return evs
		}
		time.Sleep(10 * time.Millisecond)
	}
	return m.Events()
}

// runCase replays one pcap through a fresh gateway and returns its events.
func runCase(dataDir, pcapName string) ([]*metrics.Event, error) {
	g, lg, err := buildGateway()
	if err != nil {
		return nil, err
	}
	defer g.Stop()
	defer lg.Close()

	r := gateway.NewReplay(g, filepath.Join(dataDir, "pcaps", pcapName), 0)
	if err := r.Start(); err != nil {
		return nil, err
	}
	defer r.Stop()

	// Replay runs in a goroutine and ends on EOF; the worker then classifies
	// asynchronously. Poll until events arrive and settle, or timeout.
	return waitForEvents(g.Metrics(), 1, 2*time.Second), nil
}

// evaluateCase runs a fixture and checks it against its expected spec.
func evaluateCase(dataDir, name string) caseResult {
	res := caseResult{CaseName: name}
	exp, err := loadExpected(dataDir, name)
	if err != nil {
		res.Mismatch = fmt.Sprintf("load expected: %v", err)
		res.Pass = false
		return res
	}
	res.Expected = exp

	evs, err := runCase(dataDir, name+".pcap")
	if err != nil {
		res.Mismatch = fmt.Sprintf("run case: %v", err)
		res.Pass = false
		return res
	}
	res.Events = evs
	if len(evs) == 0 {
		res.Mismatch = "no event produced (packet not decoded / no flow classified); expected at least one"
		res.Pass = false
		return res
	}
	ev := evs[0]
	res.Proto = ev.Proto
	res.Category = ev.Category
	res.Action = ev.Action
	res.Confidence = ev.Confidence

	if exp.Protocol != "" && ev.Proto != exp.Protocol {
		res.Mismatch = fmt.Sprintf("protocol mismatch: got %q, want %q", ev.Proto, exp.Protocol)
		res.Pass = false
		return res
	}
	if ev.Action != exp.ExpectedAction {
		res.Mismatch = fmt.Sprintf("action mismatch: got %q, want %q", ev.Action, exp.ExpectedAction)
		res.Pass = false
		return res
	}
	if ev.Confidence < exp.ConfidenceMin {
		res.Mismatch = fmt.Sprintf("confidence %.3f < minimum %.3f", ev.Confidence, exp.ConfidenceMin)
		res.Pass = false
		return res
	}
	res.Pass = true
	return res
}

// printTable renders the regression summary table for the case outcomes.
func printTable(results []caseResult) {
	fmt.Println("=== PCAP regression lab: results ===")
	fmt.Printf("%-12s %-5s %-8s %-8s %-10s %s\n",
		"case", "PASS", "proto", "action", "confidence", "expected")
	for _, r := range results {
		status := "FAIL"
		if r.Pass {
			status = "PASS"
		}
		fmt.Printf("%-12s %-5s %-8s %-8s %-10.4f %s\n",
			r.CaseName, status, r.Proto, r.Action, r.Confidence,
			r.Expected.Protocol+"/"+r.Expected.ExpectedAction)
	}

	// Precision/recall over the labeled expected set. TP = case passed with an
	// event, FN = no event produced for a labeled case, FP = passed mismatch
	// (different protocol/action than expected). Values we cannot truly compute
	// are reported as "unavailable"; no numbers are fabricated.
	tp, fp, fn := 0, 0, 0
	labeled := len(results)
	for _, r := range results {
		switch {
		case r.Pass && len(r.Events) > 0:
			tp++
		case len(r.Events) == 0:
			fn++
		default:
			fp++
		}
	}
	prec := "unavailable"
	if tp+fp > 0 {
		prec = fmt.Sprintf("%.3f", float64(tp)/float64(tp+fp))
	}
	rec := "unavailable"
	if labeled > 0 {
		rec = fmt.Sprintf("%.3f", float64(tp)/float64(labeled))
	}
	fmt.Printf("tp/fp/fn precision recall: %d/%d/%d precision=%s recall=%s\n",
		tp, fp, fn, prec, rec)
	fmt.Println("detection_latency: unavailable")
}
