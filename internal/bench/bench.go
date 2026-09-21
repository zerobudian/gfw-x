package bench

import (
	"fmt"
	"runtime"
	"sort"
	"time"

	"gfw-x/internal/config"
	"gfw-x/internal/detect"
	"gfw-x/internal/dpi"
	"gfw-x/internal/gateway"
	"gfw-x/internal/logging"
	"gfw-x/internal/metrics"
	"gfw-x/internal/rules"
)

// Report is the gfwx bench output.
type Report struct {
	FlowsPerSec     float64
	PacketsPerSec   float64
	ThroughputGbps  float64
	PolicyP50       time.Duration
	PolicyP95       time.Duration
	PolicyP99       time.Duration
	AllocPerOp      uint64
	MemoryMB        float64
	SlowPathFlowsPS float64
	DPIDelta        float64 // extra ns/op when DPI is enabled
	TotalBytes      uint64
}

// Run executes a benchmark suite and returns a report.
func Run(flows, worker int) (*Report, error) {
	cfg := config.DefaultConfig()
	cfg.Runtime.WorkerPool = worker
	cfg.Runtime.ChannelCapacity = 16384

	preset, _ := rules.PresetBy("developer")
	repo := rules.NewRepo()
	repo.Replace(preset.Rules)

	m := metrics.New(4096)
	logger := logging.NewPipeline(logging.RingStorage{}, 65536, true, 1.0)
	defer logger.Close()

	det := detect.NewEngine(true, cfg.Detect.Threshold, false)
	dpiEng := dpi.NewEngine(true, cfg.Default.DPI)

	rep := &Report{}

	// A) Policy decision latency (the core "policy decision" metric).
	attrs := &rules.Attributes{Domain: "api.github.com", SNI: "api.github.com", Proto: "tls", DstPort: 443}
	lats := make([]int64, 20000)
	base := repo
	for i := range lats {
		start := time.Now()
		base.Eval(attrs)
		lats[i] = time.Since(start).Nanoseconds()
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	rep.PolicyP50 = time.Duration(pct(lats, 0.50))
	rep.PolicyP95 = time.Duration(pct(lats, 0.95))
	rep.PolicyP99 = time.Duration(pct(lats, 0.99))

	// B) Fast-path pipeline throughput (gateway.Ingest + async classify).
	g := gateway.New(cfg, repo, m, logger, det, dpiEng)
	g.SetMode(config.ModeBlock)
	g.Start()

	subStart := time.Now()
	startN := m.C.Decisions.Load()
	submitKnown(g, flows)
	waitDecisions(m, startN, int64(flows))
	elapsed := time.Since(subStart).Seconds()
	rep.FlowsPerSec = float64(flows) / elapsed
	rep.PacketsPerSec = rep.FlowsPerSec * 4
	rep.TotalBytes = uint64(flows) * 1400
	rep.ThroughputGbps = float64(rep.TotalBytes) * 8 / (elapsed * 1e9)

	// C) allocations/op (deltas across the whole fast-path loop).
	var memBefore, memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)
	startN = m.C.Decisions.Load()
	submitKnown(g, flows)
	waitDecisions(m, startN, int64(flows))
	runtime.ReadMemStats(&memAfter)
	rep.AllocPerOp = (memAfter.TotalAlloc - memBefore.TotalAlloc) / uint64(flows)
	rep.MemoryMB = float64(memAfter.HeapAlloc) / (1024 * 1024)

	// D) Slow-path (detection) throughput.
	subStart = time.Now()
	startN = m.C.Decisions.Load()
	submitUnknown(g, flows)
	waitDecisions(m, startN, int64(flows))
	slowElapsed := time.Since(subStart).Seconds()
	rep.SlowPathFlowsPS = float64(flows) / slowElapsed

	// E) DPI enabled/disabled overhead on the detection path.
	rep.DPIDelta = dpiDelta()

	g.Stop()
	return rep, nil
}

func submitKnown(g *gateway.Gateway, n int) {
	sample := buildTLS("api.github.com")
	for i := 0; i < n; i++ {
		g.Ingest(&gateway.Traffic{
			SrcIP: "192.168.1.1", DstIP: "35.224.1.1",
			SrcPort: 40000, DstPort: 443, Transport: "tcp",
			Sample: sample, Category: "",
			UpBytes: 800, DownBytes: 30000, UpPkts: 2, DownPkts: 6, LifetimeSec: 10,
		})
	}
}

func submitUnknown(g *gateway.Gateway, n int) {
	feat := &detect.Features{UpDownRatio: 0.5, Alternation: 0.8, Keepalive: 30,
		BurstInterval: 2.5, Lifetime: 600, Handshake: 0.1, MinPkt: 96, MaxPkt: 1420}
	for i := 0; i < n; i++ {
		g.Ingest(&gateway.Traffic{
			SrcIP: "192.168.1.2", DstIP: "35.224.1.2",
			SrcPort: 40001, DstPort: 51820, Transport: "udp",
			Sample: []byte{1, 0, 0, 0, 0}, Category: "vpn-tunnel",
			UpBytes: 1200, DownBytes: 4000, UpPkts: 4, DownPkts: 9,
			Features: feat,
		})
	}
}

func waitDecisions(m *metrics.Registry, start int64, target int64) {
	for {
		if m.C.Decisions.Load()-start >= target {
			return
		}
		time.Sleep(500 * time.Microsecond)
	}
}

func pct(s []int64, q float64) int64 {
	if len(s) == 0 {
		return 0
	}
	return s[int(float64(len(s)-1)*q)]
}

// dpiDelta measures the incremental cost of running DPI after detection.
func dpiDelta() float64 {
	sample := buildTLS("api.openai.com")
	feat := &detect.Features{UpDownRatio: 0.4, Alternation: 0.3, Lifetime: 60, Handshake: 0.9}
	det := detect.NewEngine(true, 0.9, false)
	n := 30000
	// baseline detection only
	start := time.Now()
	for i := 0; i < n; i++ {
		det.Lookup(detect.Sample{Proto: "tcp", DstPort: 443, Data: sample}, feat)
	}
	base := time.Since(start).Seconds()
	// with DPI
	dp := dpi.NewEngine(true, 1.0)
	start = time.Now()
	for i := 0; i < n; i++ {
		det.Lookup(detect.Sample{Proto: "tcp", DstPort: 443, Data: sample}, feat)
		dp.Inspect(sample, "tcp", 443)
	}
	with := time.Since(start).Seconds()
	return (with - base) / float64(n) * 1e9 // ns/op delta
}

// buildTLS encodes a minimal TLS ClientHello carrying SNI that our parser reads.
func buildTLS(domain string) []byte {
	sni := []byte(domain)
	name := make([]byte, 0, 3+len(sni))
	name = append(name, 0x00) // name_type: host_name
	name = append(name, byte(len(sni)>>8), byte(len(sni)))
	name = append(name, sni...)
	body := append([]byte{byte(len(name) >> 8), byte(len(name))}, name...) // ServerNameList
	ext := append([]byte{0x00, 0x00, byte(len(body) >> 8), byte(len(body))}, body...)
	hello := append([]byte{0x03, 0x03}, make([]byte, 32)...) // version + random
	hello = append(hello, 0x00)                              // session id len
	hello = append(hello, 0x00, 0x02, 0x00, 0x2f)            // cipher suites
	hello = append(hello, 0x01, 0x00)                        // compression
	hello = append(hello, byte(len(ext)>>8), byte(len(ext)))
	hello = append(hello, ext...)
	hs := append([]byte{0x01, byte(len(hello) >> 16), byte(len(hello) >> 8), byte(len(hello))}, hello...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

// String renders the report as text.
func (r *Report) String() string {
	return fmt.Sprintf(
		"GFW X benchmark\n"+
			"  flows/sec       : %.0f\n"+
			"  packets/sec     : %.0f\n"+
			"  throughput      : %.3f Gbps\n"+
			"  policy p50      : %s\n"+
			"  policy p95      : %s\n"+
			"  policy p99      : %s\n"+
			"  alloc/op        : %d B\n"+
			"  memory          : %.1f MB\n"+
			"  slow-path fps   : %.0f\n"+
			"  DPI overhead    : %.3f ns/op\n",
		r.FlowsPerSec, r.PacketsPerSec, r.ThroughputGbps,
		r.PolicyP50, r.PolicyP95, r.PolicyP99,
		r.AllocPerOp, r.MemoryMB, r.SlowPathFlowsPS, r.DPIDelta)
}
