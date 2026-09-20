package metrics

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Event is one record surfaced to the live event list / analytics.
type Event struct {
	ID          uint64    `json:"id"`
	Time        time.Time `json:"time"`
	Src         string    `json:"src"`
	Dst         string    `json:"dst"`
	Proto       string    `json:"proto"`
	Domain      string    `json:"domain,omitempty"`
	SNI         string    `json:"sni,omitempty"`
	Action      string    `json:"action"`
	MatchedRule string    `json:"matched_rule,omitempty"`
	Category    string    `json:"category,omitempty"`
	Confidence  float64   `json:"confidence,omitempty"`
	BytesUp     uint64    `json:"bytes_up"`
	BytesDown   uint64    `json:"bytes_down"`
	Duration    float64   `json:"duration_sec"`
}

// Counters are atomic aggregate counters for the dashboard.
type Counters struct {
	FlowsSeen   atomic.Int64
	Packets     atomic.Int64
	Decisions   atomic.Int64
	Allowed     atomic.Int64
	Blocked     atomic.Int64
	Unknown     atomic.Int64
	Observed    atomic.Int64
	RateLimited atomic.Int64
	Rejected    atomic.Int64
	Dropped     atomic.Int64
	BytesUp     atomic.Int64
	BytesDown   atomic.Int64
	BlockedToday atomic.Int64
}

// Snapshot is a point-in-time read of counters.
type Snapshot struct {
	FlowsSeen   int64 `json:"flows_seen"`
	Packets     int64 `json:"packets"`
	Decisions   int64 `json:"decisions"`
	Allowed     int64 `json:"allowed"`
	Blocked     int64 `json:"blocked"`
	Unknown     int64 `json:"unknown"`
	Observed    int64 `json:"observed"`
	RateLimited int64 `json:"rate_limited"`
	Rejected    int64 `json:"rejected"`
	Dropped     int64 `json:"dropped"`
	BytesUp     int64 `json:"bytes_up"`
	BytesDown   int64 `json:"bytes_down"`
	BlockedToday int64 `json:"blocked_today"`
}

// Rank wraps a counted key (domain/reason/protocol).
type Rank struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// Registry holds counters, ranked tables and a bounded event ring.
type Registry struct {
	C Counters

	mu      sync.Mutex
	topDom  map[string]int64
	topRea  map[string]int64
	proto   map[string]int64
	events  []*Event
	evIdx   int
	evCap   int
	evID    uint64

	// throughput
	tm *thruMeter
}

func New(evCap int) *Registry {
	if evCap < 64 {
		evCap = 64
	}
	return &Registry{
		topDom: map[string]int64{},
		topRea: map[string]int64{},
		proto:  map[string]int64{},
		events: make([]*Event, 0, evCap),
		evCap:  evCap,
		tm:     newThruMeter(),
	}
}

// Snapshot returns copies of counters.
func (r *Registry) Snapshot() Snapshot {
	return Snapshot{
		FlowsSeen: r.C.FlowsSeen.Load(), Packets: r.C.Packets.Load(),
		Decisions: r.C.Decisions.Load(), Allowed: r.C.Allowed.Load(),
		Blocked: r.C.Blocked.Load(), Unknown: r.C.Unknown.Load(),
		Observed: r.C.Observed.Load(), RateLimited: r.C.RateLimited.Load(),
		Rejected: r.C.Rejected.Load(), Dropped: r.C.Dropped.Load(),
		BytesUp: r.C.BytesUp.Load(), BytesDown: r.C.BytesDown.Load(),
		BlockedToday: r.C.BlockedToday.Load(),
	}
}

// AddBytes updates counters and the throughput meter.
func (r *Registry) AddBytes(up, down int64) {
	r.C.BytesUp.Add(up)
	r.C.BytesDown.Add(down)
	r.tm.add(up + down)
}

// Throughput returns bytes/sec over the last window.
func (r *Registry) Throughput() int64 { return r.tm.rate() }

// RecordTopDomain records a domain occurrence.
func (r *Registry) RecordTopDomain(d string) {
	if d == "" {
		d = "(ip)"
	}
	r.mu.Lock()
	r.topDom[d]++
	r.mu.Unlock()
}

// RecordTopReason records a block reason / matched rule label.
func (r *Registry) RecordTopReason(reason string) {
	if reason == "" {
		reason = "default"
	}
	r.mu.Lock()
	r.topRea[reason]++
	r.mu.Unlock()
}

// RecordProtocol records a protocol occurrence.
func (r *Registry) RecordProtocol(p string) {
	if p == "" {
		p = "unknown"
	}
	r.mu.Lock()
	r.proto[p]++
	r.mu.Unlock()
}

// PushEvent appends to the bounded in-memory ring.
func (r *Registry) PushEvent(e *Event) {
	r.mu.Lock()
	r.evID++
	if e.ID == 0 {
		e.ID = r.evID
	}
	if len(r.events) < r.evCap {
		r.events = append(r.events, e)
	} else {
		r.events[r.evIdx] = e
		r.evIdx = (r.evIdx + 1) % r.evCap
	}
	r.mu.Unlock()
}

// Events returns events newest-first by monotonically increasing event id.
func (r *Registry) Events() []*Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Event, 0, len(r.events))
	for i := range r.events {
		if r.events[i] != nil {
			out = append(out, r.events[i])
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

// TopDomains returns top N by count.
func (r *Registry) TopDomains(n int) []Rank   { return r.rank(r.topDom, n) }
func (r *Registry) TopReasons(n int) []Rank   { return r.rank(r.topRea, n) }
func (r *Registry) ProtocolDist() []Rank      { return r.rank(r.proto, 0) }

func (r *Registry) rank(m map[string]int64, n int) []Rank {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Rank, 0, len(m))
	for k, v := range m {
		out = append(out, Rank{Key: k, Count: v})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// thruMeter implements a low-memory rolling bytes/sec window.
type thruMeter struct {
	mu     sync.Mutex
	window []thruBucket
	idx    int
}

type thruBucket struct {
	t     int64 // unix nanos
	bytes int64
}

const thruWindows = 8
const thruWidth = int64(time.Second)

func newThruMeter() *thruMeter {
	return &thruMeter{window: make([]thruBucket, thruWindows)}
}

func (t *thruMeter) add(bytes int64) {
	now := time.Now().UnixNano()
	t.mu.Lock()
	w := &t.window[t.idx]
	if now-w.t >= thruWidth {
		t.idx = (t.idx + 1) % thruWindows
		w = &t.window[t.idx]
		*w = thruBucket{t: now}
	}
	w.bytes += bytes
	t.mu.Unlock()
}

func (t *thruMeter) rate() int64 {
	now := time.Now().UnixNano()
	t.mu.Lock()
	defer t.mu.Unlock()
	var totalBytes int64
	var span int64
	for i := 0; i < thruWindows; i++ {
		w := t.window[i]
		if w.t == 0 {
			continue
		}
		age := now - w.t
		if age > thruWidth*thruWindows {
			continue // stale
		}
		totalBytes += w.bytes
		if span < age { // span = the oldest window timestamp normalized
			span = age
		}
	}
	if span == 0 {
		return 0
	}
	// rate = bytes in covered window / window span
	return totalBytes * int64(time.Second) / (span + 1)
}