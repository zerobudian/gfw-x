package gateway

import (
	"fmt"
	"strings"
	"time"
)

// PrometheusText renders the Prometheus text exposition for the gateway data
// plane. All labels have bounded cardinality — never IPs, domains, or flow IDs.
// Latency is exposed as count + sum so collectors derive averages / histograms
// without us holding per-flow state.
func (g *Gateway) PrometheusText() string {
	var b strings.Builder
	snap := g.m.Snapshot()
	flows := g.flows

	counter := func(name, help string, v int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n", name, help)
		fmt.Fprintf(&b, "# TYPE %s counter\n", name)
		fmt.Fprintf(&b, "%s %d\n", name, v)
	}
	gauge := func(name, help string, v int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n", name, help)
		fmt.Fprintf(&b, "# TYPE %s gauge\n", name)
		fmt.Fprintf(&b, "%s %d\n", name, v)
	}
	base := func(name, help string, v int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n", name, help)
		fmt.Fprintf(&b, "# TYPE %s gauge\n", name)
		fmt.Fprintf(&b, "%s %g\n", name, float64(v)/1e9)
	}

	counter("gfwx_packets_total", "Total packets observed.", snap.Packets)
	counter("gfwx_bytes_total", "Total bytes processed (up+down).", snap.BytesUp+snap.BytesDown)
	gauge("gfwx_flows_active", "Currently active classified flows.", flows.ActiveFlows())
	counter("gfwx_fast_path_hits_total", "Flow-table fast-path hits.", int64(flows.LookupHits()))
	counter("gfwx_slow_path_hits_total", "Slow-path classifications performed.", int64(g.slowPass.Load()))
	counter("gfwx_policy_evaluations_total", "Policy decisions rendered.", snap.Decisions)
	counter("gfwx_rule_hits_total", "Rule hits accounted across the active repo.", g.ruleHitsTotal())
	counter("gfwx_packets_dropped_total", "Packets dropped/blocked.", snap.Dropped+snap.Blocked)
	counter("gfwx_detector_runs_total", "Detection engine runs.", int64(g.det.Detections()))

	base("gfwx_detector_latency_seconds", "Sum of detector latency (seconds).", int64(g.detLatS.Load()))
	counter("gfwx_detector_latency_seconds_count", "Detection runs.", int64(g.detLatC.Load()))

	// Per-detector counters. The label set is the statically registered detector
	// set, so cardinality is bounded and can never grow with traffic.
	counters := g.det.DetectorCounters()
	for name, st := range counters {
		fmt.Fprintf(&b, "# HELP gfwx_detector_runs_total Total inspections for detector %s.\n", name)
		fmt.Fprintf(&b, "# TYPE gfwx_detector_runs_total counter\n")
		fmt.Fprintf(&b, "gfwx_detector_runs_total{detector=%q} %d\n", name, st.GetRuns())
		fmt.Fprintf(&b, "# HELP gfwx_detector_panics_total Panics caught for detector %s.\n", name)
		fmt.Fprintf(&b, "# TYPE gfwx_detector_panics_total counter\n")
		fmt.Fprintf(&b, "gfwx_detector_panics_total{detector=%q} %d\n", name, st.GetPanics())
	}

	base("gfwx_policy_latency_seconds", "Sum of policy latency (seconds).", int64(g.polLatS.Load()))
	counter("gfwx_policy_latency_seconds_count", "Policy evaluations.", int64(g.polLatC.Load()))

	gauge("gfwx_nfqueue_depth", "Current NFQUEUE queue depth (0 when not using NFQUEUE).", g.nfDepth.Load())
	counter("gfwx_nfqueue_overflows_total", "NFQUEUE queue-overflow drops.", g.nfOverflows.Load())

	// Shadow mode (observe-only) counters and a gauge describing whether a
	// candidate rule set is currently being validated.
	if st := g.ShadowStats(); st != nil {
		counter("gfwx_shadow_evaluations_total", "Flows evaluated against the shadow candidate set.", st["evaluations"])
		counter("gfwx_shadow_disagreements_total", "Shadow decisions that differ from the active decision.", st["disagreement"])
		counter("gfwx_shadow_would_block_total", "Flows the shadow candidate set would have blocked.", st["would_block"])
		counter("gfwx_shadow_would_allow_total", "Flows the shadow candidate set would have allowed/observed.", st["would_allow"])
	}
	gauge("gfwx_shadow_active", "1 when a shadow candidate rule set is loaded for validation.", boolToInt64(g.shadowHasCandidate()))
	gauge("gfwx_shadow_candidate_revision", "Revision id the shadow is currently validating (0 if none).", g.ShadowCandidateRevision())

	counter("gfwx_log_dropped_total", "Log records shed by the async pipeline.", g.logDropped())

	var uptime int64
	if !g.start.IsZero() {
		uptime = int64(time.Since(g.start).Seconds())
	}
	gauge("gfwx_uptime_seconds", "Gateway uptime (seconds).", uptime)
	return b.String()
}

func (g *Gateway) ruleHitsTotal() int64 {
	var total uint64
	for _, r := range g.Rules().All() {
		total += r.Hits
	}
	return int64(total)
}

func (g *Gateway) logDropped() int64 {
	st := g.LogStats()
	return st["dropped_full"] + st["dropped_sampled"]
}
