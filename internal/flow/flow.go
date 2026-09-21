package flow

import (
	"bytes"
	"encoding/binary"
	"strings"
	"sync"
	"time"
)

// Action is a gateway disposition for a flow.
type Action string

const (
	ActionAllow     Action = "allow"
	ActionBlock     Action = "block"
	ActionObserve   Action = "observe"
	ActionRateLimit Action = "ratelimit"
	ActionReject    Action = "reject"
	ActionDrop      Action = "drop"
)

// Protocol is a transport / app protocol label.
type Protocol string

// Known protocol labels.
const (
	ProtoUnknown   Protocol = "unknown"
	ProtoTCP       Protocol = "tcp"
	ProtoUDP       Protocol = "udp"
	ProtoDNS       Protocol = "dns"
	ProtoTLS       Protocol = "tls"
	ProtoQUIC      Protocol = "quic"
	ProtoHTTP      Protocol = "http"
	ProtoWireGuard Protocol = "wireguard"
	ProtoOpenVPN   Protocol = "openvpn"
	ProtoGRE       Protocol = "gre"
	ProtoICMP      Protocol = "icmp"
)

// Stats holds per-flow byte/bandwidth accounting.
type Stats struct {
	BytesUpload   uint64 // client -> server
	BytesDownload uint64 // server -> client
	PacketsUp     uint64
	PacketsDown   uint64
	FlowStart     time.Time
	FlowStop      time.Time
}

// Flow is the unit of traffic classification. The Fast Path classifies a flow
// once and then serves cached decisions for subsequent packets.
type Flow struct {
	ID      uint64
	Proto   Protocol
	SrcIP   [16]byte
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16

	// Metadata filled progressively by DNS / TLS / DPI stages.
	Domain   string // post-DNS hostname
	SNI      string // TLS server name indication
	RDNSName string // reverse lookup, if any
	ASN      uint32
	ASNName  string

	// State machine.
	Classified  bool
	Action      Action
	MatchedRule string
	Category    string
	Confidence  float64

	Sampled    bool
	Suspicious bool // flagged by detection engine for slow path

	Stats
	seeded uint8

	// mu guards the mutable, post-insert state below (Action, MatchedRule,
	// Category, Confidence, Classified, Sampled, Suspicious, and Stats byte
	// counters). Identity fields above (ID/Proto/IPs/ports/Domain/SNI) are
	// immutable after the flow is inserted and need no lock. Lock ordering:
	// a shard mutex may be held while taking a flow's mu, never the reverse.
	mu sync.Mutex
}

// SnapshotCounters returns the current upload/download byte totals. Safe for
// concurrent readers: the fast-path UpdateBytes mutates these counters on the
// resident flow, so readers must go through this accessor.
func (f *Flow) SnapshotCounters() (up, down uint64) {
	f.mu.Lock()
	up, down = f.BytesUpload, f.BytesDownload
	f.mu.Unlock()
	return
}

// IsIPv4 reports whether the flow uses IPv4 addresses (first 4 bytes valid).
func (f *Flow) IsIPv4() bool { return f.seeded&1 == 1 && f.seeded&2 == 0 }

// SetIPv4 marks the flow as IPv4 (copies into the first 4 bytes).
func (f *Flow) SetIPv4(src, dst uint32) {
	binary.BigEndian.PutUint32(f.SrcIP[0:4], src)
	binary.BigEndian.PutUint32(f.DstIP[0:4], dst)
	f.seeded |= 3
}

// SetIPv6 marks the flow as IPv6.
func (f *Flow) SetIPv6(src, dst []byte) {
	copy(f.SrcIP[:], src[:16])
	copy(f.DstIP[:], dst[:16])
	f.seeded |= 1
}

// SrcIPString returns a printable source IP.
func (f *Flow) SrcIPString() string {
	if f.seeded&1 == 0 {
		return ""
	}
	if f.IsIPv4() {
		return ip4String(f.SrcIP[:4])
	}
	return v6String(f.SrcIP[:])
}

func ip4String(b []byte) string {
	return itoa(int(b[0])) + "." + itoa(int(b[1])) + "." + itoa(int(b[2])) + "." + itoa(int(b[3]))
}

func v6String(b []byte) string {
	// Simplified but valid for display purposes.
	return fmtV6(b)
}

func fmtV6(b []byte) string {
	var out bytes.Buffer
	for i := 0; i < len(b); i += 2 {
		if i > 0 {
			out.WriteByte(':')
		}
		v := uint16(b[i])<<8 | uint16(b[i+1])
		out.WriteString(hex4(v))
	}
	return out.String()
}

func hex4(v uint16) string {
	const d = "0123456789abcdef"
	b := []byte{'0', '0', '0', '0'}
	for i := 3; i >= 0; i-- {
		b[i] = d[v&0xf]
		v >>= 4
	}
	// trim leading zeros except keep one
	s := strings.TrimLeft(string(b), "0")
	if s == "" {
		return "0"
	}
	return s
}

func itoa(v int) string {
	return uitoa(uint64(v))
}

func uitoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
