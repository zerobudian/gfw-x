package dpi

import (
	"math"
	"strings"
	"sync/atomic"
)

// Category is a coarse protocol/application classifier.
type Category string

const (
	CatUnknown     Category = "unknown"
	CatWeb         Category = "web"
	CatStreaming   Category = "streaming"
	CatP2P         Category = "p2p"
	CatTunnel      Category = "tunnel"
	CatMessage     Category = "messaging"
	CatCloud       Category = "cloud"
	CatGame        Category = "gaming"
	CatDNS         Category = "dns"
	CatMail        Category = "mail"
	CatUpdate      Category = "update"
)

// Result is the metadata-only output of one DPI inspection.
type Result struct {
	Category  Category `json:"category"`
	Proto     string   `json:"protocol"`
	App       string   `json:"app,omitempty"`
	Encrypted bool     `json:"encrypted"`
	// Content is NEVER populated: DPI inspects metadata only.
	confidence float64
}

// Engine decides which flows get DPI via sampling and refuses to inspect
// known-good traffic. It never inspects the Fast Path for normal flows.
type Engine struct {
	// enable/Ratio controls sampling.
	ratio atomic.Uint64 // float64 bits for sample ratio 0..1
	enabled atomic.Bool
	inspections atomic.Uint64
}

// NewEngine builds a DPI engine. ratio is 0..1 (% of unknown/suspicious flows).
func NewEngine(enabled bool, ratio float64) *Engine {
	e := &Engine{}
	e.enabled.Store(enabled)
	e.ratio.Store(math.Float64bits(ratio))
	return e
}

func (e *Engine) Enabled() bool       { return e.enabled.Load() }
func (e *Engine) SetEnabled(v bool)   { e.enabled.Store(v) }
func (e *Engine) Ratio() float64      { return math.Float64frombits(e.ratio.Load()) }
func (e *Engine) SetRatio(v float64)  { e.ratio.Store(math.Float64bits(v)) }
func (e *Engine) Inspections() uint64 { return e.inspections.Load() }

// ShouldInspect applies sampling to unknown/suspicious flows only. Normal and
// fully-classified flows bypass DPI entirely.
func (e *Engine) ShouldInspect(known, suspicious bool) bool {
	if !e.enabled.Load() {
		return false
	}
	if known {
		return false // fast path: normal known flows never inspected
	}
	if !suspicious {
		// apply sampling ratio to random unknown flows
		if e.Ratio() <= 0 {
			return false
		}
		// cheap pseudo-random decision derived from ratio
		if math.Float64frombits(randBits()) > e.Ratio() {
			return false
		}
	}
	return true
}

// Inspect runs metadata-only classification on a leading byte sample.
func (e *Engine) Inspect(sample []byte, proto string, dstPort uint16) (Result, bool) {
	if !e.Enabled() {
		return Result{Category: CatUnknown}, false
	}
	e.inspections.Add(1)
	r := classify(sample, proto, dstPort)
	return r, true
}

func classify(sample []byte, proto string, port uint16) Result {
	p := strings.ToLower(proto)
	// TLS / HTTP over TLS
	if len(sample) >= 3 && sample[0] == 0x16 && sample[1] == 0x03 {
		return Result{Category: CatWeb, Proto: "tls", Encrypted: true}
	}
	if len(sample) >= 4 && strings.HasPrefix(strings.ToLower(string(sample)), "http/") {
		return Result{Category: CatWeb, Proto: "http2", Encrypted: true}
	}
	if len(sample) >= 4 && (bytesHasPrefixFold(sample, "get ") || bytesHasPrefixFold(sample, "post ") || bytesHasPrefixFold(sample, "host ")) {
		return Result{Category: CatWeb, Proto: "http", App: sniffApp(sample)}
	}
	// DNS
	if p == "udp" && port == 53 {
		return Result{Category: CatDNS, Proto: "dns"}
	}
	// Mail ports
	if port == 25 || port == 465 || port == 587 || port == 993 || port == 995 {
		return Result{Category: CatMail, Proto: "mail", Encrypted: port == 465 || port == 993 || port == 995}
	}
	// streaming CDNs
	if p == "udp" && (port == 443 || port == 1935) {
		return Result{Category: CatStreaming, Proto: "stream", Encrypted: true}
	}
	// NOTE: no bare-high-port UDP heuristic. Port alone is not a reliable
	// signature for "gaming" — it would misclassify QUIC (443), WireGuard
	// (51820), and most voice/RTC/DoH traffic. Gaming can only be inferred
	// from an actual application signature in the sample (to be added).
	return Result{Category: CatUnknown, Proto: p}
}

func sniffApp(sample []byte) string {
	s := strings.ToLower(string(sample))
	switch {
	case strings.Contains(s, "youtube") || strings.Contains(s, "googlevideo"):
		return "youtube"
	case strings.Contains(s, "vimeo"):
		return "vimeo"
	case strings.Contains(s, "amazon"):
		return "amazon"
	}
	return ""
}

func bytesHasPrefixFold(b []byte, prefix string) bool {
	if len(b) < len(prefix) {
		return false
	}
	return strings.EqualFold(string(b[:len(prefix)]), prefix)
}

var randCounter atomic.Uint64

func randBits() uint64 {
	// xorshift-ish PRNG for cheap sampling decisions (not cryptographic).
	v := randCounter.Add(1)
	v ^= v << 13
	v ^= v >> 7
	v ^= v << 17
	return v
}