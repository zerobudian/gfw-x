package detect

// FingerprintDetector applies static protocol fingerprinting to the leading
// bytes of a connection and reports a base protocol + confidence. It is
// stateless: Inspect is a pure function of its Sample.
type FingerprintDetector struct {
	info DetectorInfo
}

// NewFingerprintDetector builds the built-in protocol-fingerprint detector.
func NewFingerprintDetector() *FingerprintDetector {
	return &FingerprintDetector{info: DetectorInfo{
		Name:        "fingerprint",
		Description: "static TCP/UDP/QUIC/WireGuard/TLS/HTTP-CONNECT/SOCKS packet fingerprinting",
	}}
}

func (d *FingerprintDetector) Info() DetectorInfo { return d.info }

func (d *FingerprintDetector) Inspect(s Sample, f Features) Result {
	fp := fingerprint(s)
	return Result{Protocol: fp.protocol, Confidence: fp.confidence, Reasons: fp.reasons}
}

// BehaviorDetector scores a flow by traffic shape (upload ratio, burst
// alternation, keepalive cadence, lifetime) independent of ports. It contributes
// a confidence delta and matching evidence, with no protocol label.
type BehaviorDetector struct {
	info DetectorInfo
}

// NewBehaviorDetector builds the built-in behavioral detector.
func NewBehaviorDetector() *BehaviorDetector {
	return &BehaviorDetector{info: DetectorInfo{
		Name:        "behavior",
		Description: "traffic-shape heuristics (ratio, alternation, keepalive, burst, lifetime)",
	}}
}

func (d *BehaviorDetector) Info() DetectorInfo { return d.info }

func (d *BehaviorDetector) Inspect(s Sample, f Features) Result {
	var conf float64
	var reasons []string
	for _, br := range behavior(&f) {
		reasons = append(reasons, br.reason)
		conf += br.delta
	}
	return Result{Protocol: "", Confidence: conf, Reasons: reasons}
}
