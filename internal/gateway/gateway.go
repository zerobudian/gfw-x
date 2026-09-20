package gateway

import (
	"net"
	"sync/atomic"
	"time"

	"gfw-x/internal/config"
	"gfw-x/internal/detect"
	"gfw-x/internal/dpi"
	"gfw-x/internal/dns"
	"gfw-x/internal/flow"
	"gfw-x/internal/logging"
	"gfw-x/internal/metrics"
	"gfw-x/internal/policy"
	"gfw-x/internal/rules"
	"gfw-x/internal/tls"
)

// Traffic is the data-plane input produced by a packet source (interface
// capture, pcap, or the in-process synthetic generator).
type Traffic struct {
	SrcIP, DstIP string
	SrcPort      uint16
	DstPort      uint16
	Transport    string // "tcp" | "udp"
	Sample       []byte // leading payload bytes (may be nil)
	// Category is assigned by an external domain classifier (or the generator)
	// and feeds BLOCK_CATEGORY rules.
	Category    string
	UpBytes     uint64
	DownBytes   uint64
	UpPkts      uint64
	DownPkts    uint64
	Features    *detect.Features
	LifetimeSec float64
}

// job is a pending first-classification for a worker.
type job struct {
	t *Traffic
	f *flow.Flow
}

// Gateway runs the Fast Path / Slow Path data-plane architecture.
type Gateway struct {
	cfg    *config.Config
	mode   atomic.Int32 // index into config.ValidModes
	flows  *flow.Table
	repo   atomic.Pointer[rules.RuleRepo]
	pol    atomic.Pointer[policy.Engine]
	det    *detect.Engine
	dpiEng *dpi.Engine
	m      *metrics.Registry
	logger *logging.Pipeline

	fast   chan *job // bounded
	slow   chan *job // bounded
	stopCh chan struct{}

	start time.Time

	classifies atomic.Uint64
	slowPass   atomic.Uint64
}

// New builds a gateway. Call Start to launch workers.
func New(cfg *config.Config, repo *rules.RuleRepo, m *metrics.Registry, logger *logging.Pipeline, det *detect.Engine, d *dpi.Engine) *Gateway {
	g := &Gateway{
		cfg:    cfg,
		det:    det,
		dpiEng: d,
		m:      m,
		logger: logger,
		flows:  flow.NewTable(cfg.Runtime.FlowShards, time.Duration(cfg.Runtime.FlowTTL)*time.Second),
		fast:   make(chan *job, cfg.Runtime.ChannelCapacity),
		slow:   make(chan *job, cfg.Runtime.ChannelCapacity),
		stopCh: make(chan struct{}),
		start:  time.Now(),
	}
	g.SetMode(cfg.Default.Mode)
	g.repo.Store(repo)
	g.pol.Store(policy.NewEngine(repo))
	return g
}

// Start launches the fixed worker pools and the flow sweeper.
func (g *Gateway) Start() {
	for i := 0; i < g.cfg.Runtime.WorkerPool; i++ {
		go g.fastWorker()
		go g.slowWorker()
	}
	go g.sweeper()
}

// Stop halts workers.
func (g *Gateway) Stop() {
	select {
	case <-g.stopCh:
	default:
		close(g.stopCh)
	}
}

// Mode returns the current run mode.
func (g *Gateway) Mode() config.Mode { return modeByIndex(int(g.mode.Load())) }

// SetMode switches run mode in-place — no service rebuild.
func (g *Gateway) SetMode(m config.Mode) error {
	i := indexOfMode(m)
	if i < 0 {
		return ErrInvalidMode
	}
	g.mode.Store(int32(i))
	return nil
}

// SetActiveRepo swaps the active rule repo (Custom mode). The swap is atomic
// so workers observe either the old or the new (repo, engine) pair, never a
// torn mix.
func (g *Gateway) SetActiveRepo(repo *rules.RuleRepo) {
	eng := policy.NewEngine(repo)
	g.pol.Store(eng)
	g.repo.Store(repo)
}

// Exported accessors for the dashboard / API.
func (g *Gateway) Table() *flow.Table              { return g.flows }
func (g *Gateway) Metrics() *metrics.Registry      { return g.m }
func (g *Gateway) Rules() *rules.RuleRepo          { return g.repo.Load() }
func (g *Gateway) Detector() *detect.Engine        { return g.det }
func (g *Gateway) Classifies() (c, slow uint64)    { return g.classifies.Load(), g.slowPass.Load() }
func (g *Gateway) Uptime() time.Time               { return g.start }

// LogStats returns logging pipeline shedding counters.
func (g *Gateway) LogStats() map[string]int64 {
	written, droppedA, droppedB, counters := g.logger.Stats()
	return map[string]int64{
		"written": int64(written), "dropped_full": int64(droppedA),
		"dropped_sampled": int64(droppedB), "counters_only": int64(counters),
	}
}

// ErrInvalidMode is returned for bad mode names.
var ErrInvalidMode = &modeError{}

type modeError struct{}

func (modeError) Error() string { return "invalid gateway mode" }

// Ingest is the Fast-Path entry point for every classification event.
func (g *Gateway) Ingest(t *Traffic) string {
	g.m.C.Packets.Add(1)

	if g.Mode() == config.ModeBypass {
		return g.bypassIngest(t)
	}

	f := g.flowFromTraffic(t)
	// Fast path: already-classified flow → serve cached decision.
	if cached, ok := g.flows.LookupFlow(f); ok {
		g.flows.UpdateFlow(cached, t.UpBytes, t.DownBytes, t.UpPkts, t.DownPkts)
		g.m.AddBytes(int64(t.UpBytes), int64(t.DownBytes))
		g.metricsDecision(string(cached.Action))
		return string(cached.Action)
	}

	g.classifies.Add(1)
	j := &job{t: t, f: f}
	if f.Suspicious || (f.Domain == "" && f.SNI == "") {
		// Unknown / suspicious flow → Slow Path (detection + optional DPI).
		g.slowPass.Add(1)
		select {
		case g.slow <- j:
			return ""
		default:
			return g.observeDrop(t)
		}
	}
	// Known flow → Fast Path worker (single classification).
	select {
	case g.fast <- j:
		return ""
	default:
		return g.observeDrop(t)
	}
}

// flowFromTraffic builds a Flow and extracts DNS / TLS metadata from a sample.
func (g *Gateway) flowFromTraffic(t *Traffic) *flow.Flow {
	f := &flow.Flow{
		Proto:    transportToProto(t.Transport),
		SrcPort:  t.SrcPort,
		DstPort:  t.DstPort,
		Category: t.Category,
	}
	if src := net.ParseIP(t.SrcIP); src != nil {
		if v4 := src.To4(); v4 != nil {
			f.SrcIP[0], f.SrcIP[1], f.SrcIP[2], f.SrcIP[3] = v4[0], v4[1], v4[2], v4[3]
		} else {
			copy(f.SrcIP[:], src.To16()[:16])
		}
	}
	if dst := net.ParseIP(t.DstIP); dst != nil {
		if v4 := dst.To4(); v4 != nil {
			f.DstIP[0], f.DstIP[1], f.DstIP[2], f.DstIP[3] = v4[0], v4[1], v4[2], v4[3]
		} else {
			copy(f.DstIP[:], dst.To16()[:16])
		}
	}
	if len(t.Sample) > 0 {
		g.metadataFromSample(f, t)
	}
	return f
}

func (g *Gateway) metadataFromSample(f *flow.Flow, t *Traffic) {
	if t.Transport == "udp" && (t.DstPort == 53 || t.SrcPort == 53) {
		if q, err := dns.Query(t.Sample); err == nil {
			f.Domain = q.Name
			f.Proto = flow.ProtoDNS
		}
		return
	}
	if ch, err := tls.ParseClientHello(t.Sample); err == nil && ch.HasSNI() {
		f.SNI = ch.SNI
		f.Proto = flow.ProtoTLS
		if f.Domain == "" {
			f.Domain = ch.SNI
		}
	}
}

// fastWorker classifies known flows.
func (g *Gateway) fastWorker() {
	for {
		select {
		case <-g.stopCh:
			return
		case j := <-g.fast:
			g.finish(j, false)
		}
	}
}

// slowWorker runs detection + sampled DPI for unknown / suspicious flows.
func (g *Gateway) slowWorker() {
	for {
		select {
		case <-g.stopCh:
			return
		case j := <-g.slow:
			g.finish(j, true)
		}
	}
}

func (g *Gateway) finish(j *job, slow bool) {
	f := j.f
	a := &rules.Attributes{
		Domain:   f.Domain,
		SNI:      f.SNI,
		Proto:    string(f.Proto),
		SrcPort:  f.SrcPort,
		DstPort:  f.DstPort,
		Category: f.Category,
	}
	ip := net.IP(f.SrcIP[:]); if ip != nil { a.SrcIP = ip }
	ip2 := net.IP(f.DstIP[:]); if ip2 != nil { a.DstIP = ip2 }

	var detRep *policy.DetectionReport
	cat := f.Category
	if slow {
		// Slow Path: detection engine + optional sampled DPI.
		det := g.det.Lookup(detect.Sample{
			Proto:   j.t.Transport,
			DstPort: f.DstPort,
			Data:    j.t.Sample,
			SNI:     f.SNI,
		}, j.t.Features)
		detRep = &policy.DetectionReport{
			Protocol: det.Protocol, Confidence: det.Confidence,
			AutoApply: det.AutoApply, Action: string(det.Action),
		}
		f.Confidence = det.Confidence
		f.Suspicious = true
		if g.dpiEng.ShouldInspect(false, det.Confidence >= 0.5) && len(j.t.Sample) > 0 {
			res, _ := g.dpiEng.Inspect(j.t.Sample, j.t.Transport, f.DstPort)
			cat = string(res.Category)
		}
	}

	// Load one engine snapshot; use its embedded repo for hit accounting so
	// Decide and RecordHit always observe the same rule set.
	eng := g.pol.Load()
	fd := eng.Decide(&policy.Input{
		Attributes: a, Detection: detRep, DPICat: cat, Mode: g.Mode(),
	})
	f.Action = flow.Action(fd.Action)
	f.MatchedRule = fd.MatchedRule
	// Account hit counters for every rule that contributed to this decision.
	eng.RuleRepo.RecordHit(fd.MatchedRules)
	if cat != "" && fd.Category == "" {
		f.Category = cat
	}
	f.Classified = true

	// cache decision by inserting the (now classified) flow.
	g.flows.InsertFlow(f)
	g.flows.UpdateFlow(f, j.t.UpBytes, j.t.DownBytes, j.t.UpPkts, j.t.DownPkts)
	g.m.AddBytes(int64(j.t.UpBytes), int64(j.t.DownBytes))
	g.metricsDecision(fd.Action)
	if fd.Detected != "" {
		g.m.RecordTopReason("detect:" + fd.Detected)
	}
	g.emit(f, fd)
}

// --- helpers ---

func (g *Gateway) bypassIngest(t *Traffic) string {
	g.m.AddBytes(int64(t.UpBytes), int64(t.DownBytes))
	g.m.C.Observed.Add(1)
	return string(flow.ActionObserve)
}

func (g *Gateway) observeDrop(t *Traffic) string {
	g.m.AddBytes(int64(t.UpBytes), int64(t.DownBytes))
	g.m.C.Observed.Add(1)
	return string(flow.ActionObserve)
}

func (g *Gateway) metricsDecision(action string) {
	g.m.C.Decisions.Add(1)
	switch flow.Action(action) {
	case flow.ActionAllow:
		g.m.C.Allowed.Add(1)
	case flow.ActionBlock, flow.ActionReject, flow.ActionDrop:
		g.m.C.Blocked.Add(1)
		g.m.C.BlockedToday.Add(1)
	case flow.ActionObserve:
		g.m.C.Observed.Add(1)
	case flow.ActionRateLimit:
		g.m.C.RateLimited.Add(1)
	default:
		g.m.C.Unknown.Add(1)
	}
}

func (g *Gateway) emit(f *flow.Flow, fd policy.FinalDecision) {
	// Snapshot the byte counters under the flow lock; UpdateBytes (fast path)
	// mutates them on the same resident flow from other workers. Category is
	// immutable after publish so it can be read directly.
	up, down := f.SnapshotCounters()
	ev := &metrics.Event{
		Time:        time.Now(),
		Src:         srcStr(f.SrcIP),
		Dst:         dstStr(f.DstIP),
		Proto:       string(f.Proto),
		Domain:      f.Domain,
		SNI:         f.SNI,
		Action:      fd.Action,
		MatchedRule: fd.MatchedRule,
		Category:    f.Category,
		Confidence:  fd.Confidence,
		BytesUp:     up,
		BytesDown:   down,
	}
	g.m.PushEvent(ev)
	g.logger.Submit(ev)
	g.m.RecordTopDomain(firstNonEmpty(f.Domain, f.SNI))
	g.m.RecordProtocol(string(f.Proto))
	if fd.MatchedRule != "" && fd.Action != "allow" {
		g.m.RecordTopReason(fd.MatchedRule)
	}
}

func (g *Gateway) sweeper() {
	ttl := time.Duration(g.cfg.Runtime.FlowTTL) * time.Second
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	tk := time.NewTicker(ttl * 2)
	defer tk.Stop()
	for {
		select {
		case <-g.stopCh:
			return
		case <-tk.C:
			g.flows.Sweep()
		}
	}
}

func transportToProto(s string) flow.Protocol {
	switch s {
	case "tcp":
		return flow.ProtoTCP
	case "udp":
		return flow.ProtoUDP
	case "icmp":
		return flow.ProtoICMP
	}
	return flow.ProtoUnknown
}

func modeByIndex(i int) config.Mode {
	if i < 0 || i >= len(config.ValidModes) {
		return config.ModeBypass
	}
	return config.ValidModes[i]
}

func indexOfMode(m config.Mode) int {
	for i, v := range config.ValidModes {
		if v == m {
			return i
		}
	}
	return -1
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func srcStr(ip [16]byte) string { return ipStr(ip, 0) }
func dstStr(ip [16]byte) string { return ipStr(ip, 0) }

func ipStr(ip [16]byte, _ int) string {
	// IPv4-style short display if high bytes empty.
	if ip[4]|ip[5]|ip[6]|ip[7]|ip[8]|ip[9]|ip[10]|ip[11]|ip[12]|ip[13]|ip[14]|ip[15] == 0 {
		return itoa(ip[0]) + "." + itoa(ip[1]) + "." + itoa(ip[2]) + "." + itoa(ip[3])
	}
	return net.IP(ip[:]).String()
}

func itoa(v byte) string {
	switch v {
	case 0: return "0"
	case 1: return "1"
	}
	return strconvU(int(v))
}

func strconvU(v int) string {
	if v == 0 { return "0" }
	var b [4]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}