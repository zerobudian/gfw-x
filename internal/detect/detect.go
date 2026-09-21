package detect

import (
	"bytes"
	"math"
	"strings"
	"sync/atomic"
)

// Action mirrors the gateway disposition but is decoupled so that detection
// only *reports* a recommendation while policy decides the final action.
type Action string

const (
	ActionAllow     Action = "allow"
	ActionObserve   Action = "observe"
	ActionRateLimit Action = "ratelimit"
	ActionReject    Action = "reject"
	ActionDrop      Action = "drop"
)

// Detection is the output of the Detection Engine. The engine does NOT apply
// this action itself; policy/pipeline decides what to do.
type Detection struct {
	Protocol   string   `json:"protocol"`
	Confidence float64  `json:"confidence"`
	Reasons    []string `json:"reasons"`
	Action     Action   `json:"suggested_action"`
	AutoApply  bool     `json:"auto_apply"` // only when >= threshold
}

// Feature is a single behavioral measurement fed to the engine.
type Features struct {
	// Mean packet size in each direction.
	UpMean, DownMean float64
	MinPkt, MaxPkt   int
	// Fraction of long (>512B) bursts that alternate (ping-pong).
	Alternation float64
	// Connection lifetime seconds.
	Lifetime float64
	// Keepalive period seconds (0 if none).
	Keepalive float64
	// Burst interval seconds.
	BurstInterval float64
	// Ratio of upstream to downstream bytes.
	UpDownRatio float64
	// Handshake completeness (0 none .. 1 full exchange).
	Handshake float64
}

// Sample is the first bytes of a connection (for fingerprinting).
type Sample struct {
	Proto   string // transport label: tcp / udp
	DstPort uint16
	Data    []byte // leading bytes
	SNI     string // TLS SNI when known
}

// Engine performs protocol / tunnel detection by aggregating the verdicts of
// all statically registered Detector plugins. Detectors are ABI-stable through
// internal/detect.Detector; adding one requires registering it (see Register)
// without touching the data-plane loop.
type Engine struct {
	enabled   atomic.Bool
	autoApply atomic.Bool
	threshold atomic.Uint64 // float64 bits

	detections atomic.Uint64

	reg *Registry
}

// NewEngine returns an Engine with the default built-in detectors registered.
func NewEngine(enabled bool, threshold float64, autoApply bool) *Engine {
	e := &Engine{reg: NewRegistry()}
	e.Register(NewFingerprintDetector())
	e.Register(NewBehaviorDetector())
	e.SetEnabled(enabled)
	e.SetAutoApply(autoApply)
	e.SetThreshold(threshold)
	return e
}

// Register adds a Detector plugin and its per-detector counters.
func (e *Engine) Register(d Detector) { e.reg.Register(d) }

// DetectorCounters returns per-detector run/panic observability counters,
// keyed by detector name (bounded cardinality).
func (e *Engine) DetectorCounters() map[string]DetectorStats { return e.reg.StatsSnapshot() }

// SetEnabled / SetAutoApply / SetThreshold are config methods.
func (e *Engine) SetEnabled(v bool)      { e.enabled.Store(v) }
func (e *Engine) SetAutoApply(v bool)    { e.autoApply.Store(v) }
func (e *Engine) Enabled() bool          { return e.enabled.Load() }
func (e *Engine) AutoApply() bool        { return e.autoApply.Load() }
func (e *Engine) SetThreshold(v float64) { e.threshold.Store(math.Float64bits(v)) }
func (e *Engine) Threshold() float64     { return math.Float64frombits(e.threshold.Load()) }
func (e *Engine) Detections() uint64     { return e.detections.Load() }

// Lookup analyzes a sample + features and returns a report. It runs every
// registered detector under a panic guard and aggregates their verdicts: the
// protocol comes from the highest-confidence protocol-bearing detector and the
// confidence is the sum of all detector confidences (clamped to 0..1).
func (e *Engine) Lookup(s Sample, f *Features) Detection {
	if !e.enabled.Load() {
		return Detection{Protocol: "none", Action: ActionAllow}
	}
	e.detections.Add(1)

	var (
		proto    string
		conf     float64
		reasons  []string
		bestConf float64
	)
	feats := Features{}
	if f != nil {
		feats = *f
	}
	for _, d := range e.reg.Detectors() {
		res := e.reg.SafeInspect(d, s, feats)
		conf += res.Confidence
		reasons = append(reasons, res.Reasons...)
		// The protocol label comes from the detector asserting one with the
		// highest confidence (fingerprint typically wins).
		if res.Protocol != "" && res.Confidence >= bestConf {
			bestConf = res.Confidence
			proto = res.Protocol
		}
	}
	if conf < 0 {
		conf = 0
	}
	if conf > 1 {
		conf = 1
	}
	d := Detection{
		Protocol:   proto,
		Confidence: conf,
		Reasons:    reasons,
		Action:     suggest(conf),
	}
	d.AutoApply = e.autoApply.Load() && conf >= e.Threshold()
	return d
}

func suggest(conf float64) Action {
	switch {
	case conf >= 0.9:
		return ActionReject
	case conf >= 0.75:
		return ActionRateLimit
	case conf >= 0.5:
		return ActionObserve
	default:
		return ActionAllow
	}
}

// --- Protocol fingerprinting ---

type fpResult struct {
	protocol   string
	confidence float64
	reasons    []string
}

func fingerprint(s Sample) fpResult {
	proto := strings.ToLower(s.Proto)
	if s.SNI != "" {
		// Known low-risk SNI tunneling is not assumed.
		return fpResult{protocol: "tls", confidence: 0.02, reasons: []string{"TLS with SNI, expected"}}
	}
	switch proto {
	case "udp":
		return fpUDP(s)
	case "tcp":
		return fpTCP(s)
	}
	return fpResult{protocol: "unknown", confidence: 0.05, reasons: []string{strings.ToLower(s.Proto) + " undetermined"}}
}

func fpUDP(s Sample) fpResult {
	// WireGuard: first byte 0x01, bytes 4..8 are 0x00.
	if len(s.Data) >= 15 && s.Data[0] == 1 {
		zero := true
		for _, b := range s.Data[4:15] {
			if b != 0 {
				zero = false
				break
			}
		}
		if zero {
			return fpResult{"wireguard", 0.95, []string{"WireGuard packet header signature", "fixed-zero reserved field"}}
		}
	}
	// QUIC: version in bytes 1..4 (0x00000001 or 0x1...Google versions).
	if len(s.Data) >= 17 && s.Data[0]>>4 == 0x0 {
		// Could be QUIC v1/v2 or Google variant.
		return fpResult{"quic", 0.6, []string{"QUIC long header shape"}}
	}
	return fpResult{"unknown", 0.15, []string{"UDP, no known fingerprint"}}
}

func fpTCP(s Sample) fpResult {
	d := s.Data
	// TLS
	if len(d) >= 5 && d[0] == 0x16 && d[1] == 0x03 {
		if d[2] >= 0x01 && d[2] <= 0x04 {
			return fpResult{"tls", 0.05, []string{"TLS handshake"}}
		}
	}
	// HTTP CONNECT proxy
	if len(d) >= 12 && bytes.HasPrefix(d, []byte("CONNECT ")) {
		return fpResult{"http_connect", 0.7, []string{"HTTP CONNECT tunnel request"}}
	}
	// SOCKS4
	if len(d) >= 10 && d[0] == 0x04 {
		return fpResult{"socks4", 0.6, []string{"SOCKS4 handshake"}}
	}
	// SOCKS5
	if len(d) >= 3 && d[0] == 0x05 {
		return fpResult{"socks5", 0.6, []string{"SOCKS5 greeting"}}
	}
	// OpenVPN: first byte TLS-ish or 0x38 style; detect TCP OpenVPN magic 0x38
	if len(d) >= 2 && d[0] == 0x38 && (d[1]&0x0F == 0x0D || d[1]&0x0F == 0x00) {
		return fpResult{"openvpn", 0.7, []string{"OpenVPN TCP header"}}
	}
	return fpResult{"unknown", 0.1, []string{"TCP no fingerprint"}}
}

// --- Behavioral profile ---
type br struct {
	reason string
	delta  float64
}

// behavior scores a flow using traffic shape independent of ports.
func behavior(f *Features) []br {
	var out []br
	if f == nil {
		return out
	}
	// Upload-heavier than download is unusual for browsing.
	if f.UpDownRatio > 1.5 {
		out = append(out, br{"upload-heavy traffic ratio", 0.15})
	}
	// Perfect alternation (long bursts swapping) suggests tunneling.
	if f.Alternation > 0.7 && f.MinPkt > 100 {
		out = append(out, br{"high burst alternation", 0.15})
	}
	// Suspicious keepalive cadence (~10-60s) common to tunnels.
	if f.Keepalive > 0 && f.Keepalive < 90 {
		out = append(out, br{"tunnel-like keepalive cadence", 0.1})
	}
	// Very regular burst interval.
	if f.BurstInterval > 0 && f.BurstInterval < 5 && f.Handshake < 0.5 {
		out = append(out, br{"regular short burst interval", 0.1})
	}
	// Long-lived connection without application handshake.
	if f.Lifetime > 300 && f.Handshake < 0.3 {
		out = append(out, br{"long-lived without handshake", 0.2})
	}
	return out
}
