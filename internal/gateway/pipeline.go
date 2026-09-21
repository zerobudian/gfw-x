package gateway

import (
	"context"
	"sync"
	"time"

	"gfw-x/internal/flow"
	"gfw-x/internal/pipeline"
	"gfw-x/internal/policy"
)

// ProcessingContext carries the structured explanation for a decided packet.
// It is returned to a PacketSink so the provider (e.g. NFQUEUE verdict) can
// log/record the reasoning alongside the verdict.
type ProcessingContext struct {
	Trace   *policy.DecisionTrace `json:"trace,omitempty"`
	Source  policy.ActionSource   `json:"source"`
	Path    policy.TracePath      `json:"path"`
	Latency time.Duration         `json:"latency_ns,omitempty"`
	Shadow  *policy.ShadowReport  `json:"shadow,omitempty"`
}

// traceRing is a bounded store of recent decision traces for the explain API.
type traceRing struct {
	mu   sync.Mutex
	buf  []*policy.DecisionTrace
	idx  int
	cap  int
	next uint64
}

func newTraceRing(cap int) *traceRing {
	if cap < 16 {
		cap = 1024
	}
	return &traceRing{buf: make([]*policy.DecisionTrace, cap), idx: 0, cap: cap}
}

func (r *traceRing) add(t *policy.DecisionTrace) {
	r.mu.Lock()
	r.buf[r.idx] = t
	r.idx = (r.idx + 1) % r.cap
	if r.next < uint64(r.cap) {
		r.next++
	}
	r.mu.Unlock()
}

// recent returns the newest traces, newest-first.
func (r *traceRing) recent(n int) []*policy.DecisionTrace {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || n > len(r.buf) {
		n = len(r.buf)
	}
	out := make([]*policy.DecisionTrace, 0, n)
	for i := 1; i <= n && i <= int(r.next); i++ {
		pos := (r.idx - i + r.cap) % r.cap
		if t := r.buf[pos]; t != nil {
			out = append(out, t)
		}
	}
	return out
}

// HandlePacket is the unified do-decide entry shared by every PacketSource
// (PCAP replay, NFQUEUE, future AF_XDP). It decodes the frame, builds Traffic,
// runs the fast/slow pipeline and returns the Verdict. Trace/sample + shadow
// recoding happen inside for observability without taxing the hot return path.
func (g *Gateway) HandlePacket(ctx context.Context, p *pipeline.Packet) pipeline.Verdict {
	in, err := pipeline.DecodePacket(p)
	if err != nil || in == nil {
		// Non-classifiable (ARP/ICMP/bare IP) or malformed: don't drop in a
		// live gateway — observe and let the kernel decide by other rules.
		return pipeline.Verdict(flow.ActionObserve)
	}
	t := &Traffic{
		SrcIP:       in.SrcIP,
		DstIP:       in.DstIP,
		SrcPort:     in.SrcPort,
		DstPort:     in.DstPort,
		Transport:   in.Transport,
		Sample:      in.Payload,
		UpBytes:     uint64(len(in.Payload)),
		UpPkts:      1,
		LifetimeSec: 0.5,
	}
	a := g.Ingest(t)
	return pipeline.Verdict(a)
}

// traceGate reports whether a decision trace should be produced for this flow.
// Fast path allocates no trace when sampling is off.
func (g *Gateway) traceGate() *policy.DecisionTrace {
	if g.cfg.Runtime.TraceSampleRatio <= 0 {
		return nil
	}
	if !policy.TraceEnabled(g.cfg.Runtime.TraceSampleRatio) {
		return nil
	}
	return policy.NewDecisionTrace()
}

// recordTrace stores a decision trace and pulls IPs into it. Latency is the
// policy-decide duration (from trace creation to record).
func (g *Gateway) recordTrace(tr *policy.DecisionTrace, f *flow.Flow) {
	tr.FlowID = f.ID
	tr.SrcIP = f.SrcIPString()
	tr.DstIP = dstStr(f.DstIP)
	tr.SrcPort = f.SrcPort
	tr.DstPort = f.DstPort
	tr.Proto = string(f.Proto)
	tr.DNSDomain = f.Domain
	tr.SNI = f.SNI
	if tr.LatencyNS == 0 {
		tr.LatencyNS = time.Since(tr.Time).Nanoseconds()
	}
	g.traces.add(tr)
}

// RecentTraces returns the newest decision traces.
func (g *Gateway) RecentTraces(n int) []*policy.DecisionTrace {
	if g.traces == nil {
		return nil
	}
	return g.traces.recent(n)
}
