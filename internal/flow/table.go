package flow

import (
	"hash/maphash"
	"sync"
	"sync/atomic"
	"time"
)

// key is the shard-local lookup key for a flow (5-tuple).
type key struct {
	src [16]byte
	dst [16]byte
	p   Protocol
	sp  uint16
	dp  uint16
}

// entry wraps a flow with a small collision chain in its shard.
type entry struct {
	k      key
	f      *Flow
	insert time.Time
	next   *entry
}

const fixedBuckets = 256 // buckets per shard (power of two)

// shard is one partition of the flow table with its own mutex.
type shard struct {
	mu      sync.Mutex
	buckets []*entry
	seed    maphash.Seed
	ttl     time.Duration
	now     func() time.Time
}

// Table is a sharded, lock-striped flow table.
type Table struct {
	shards []*shard
	mask   uint64
	active atomic.Int64 // number of live flows
	hits   atomic.Uint64
	misses atomic.Uint64
	next   atomic.Uint64 // flow id source
}

// NewTable returns a table with n shards (rounded up to a power of two).
func NewTable(n int, ttl time.Duration) *Table {
	if n < 1 {
		n = 1
	}
	// Round up to power of two.
	p := 1
	for p < n {
		p <<= 1
	}
	tab := &Table{mask: uint64(p) - 1}
	now := time.Now
	tab.shards = make([]*shard, p)
	for i := 0; i < p; i++ {
		tab.shards[i] = &shard{
			buckets: make([]*entry, fixedBuckets),
			seed:    maphash.MakeSeed(),
			ttl:     ttl,
			now:     now,
		}
	}
	return tab
}

// ShardCount returns the number of shards.
func (t *Table) ShardCount() int { return len(t.shards) }

// ActiveFlows returns the number of live flows.
func (t *Table) ActiveFlows() int64 { return t.active.Load() }

// Stats exposes counter hits.
func (t *Table) LookupHits() uint64   { return t.hits.Load() }
func (t *Table) LookupMisses() uint64 { return t.misses.Load() }

// sel picks the shard and bucket index for k.
func (t *Table) sel(k *key) (*shard, int) {
	sh := t.shards[0]
	if t.mask > 0 {
		// derive shard from key bytes cheaply.
		h := fnv1aKey(k)
		sh = t.shards[h&t.mask]
	}
	seed := sh.seed
	h := maphash.Hash{}
	h.SetSeed(seed)
	_, _ = h.Write(k.src[:])
	_, _ = h.Write(k.dst[:])
	h.WriteString(string(k.p))
	h.Write([]byte{byte(k.sp), byte(k.sp >> 8), byte(k.dp), byte(k.dp >> 8)})
	return sh, int(h.Sum64() & (fixedBuckets - 1))
}

// fnv1aKey is a fast non-cryptographic mix used only for shard selection.
func fnv1aKey(k *key) uint64 {
	const off = uint64(14695981039346656037)
	const prime = uint64(1099511628211)
	h := off
	h = (h ^ uint64(k.sp)) * prime
	h = (h ^ uint64(k.dp)) * prime
	h = (h ^ uint64(k.p[0])) * prime
	for i := 0; i < 16; i++ {
		h = (h ^ uint64(k.src[i])) * prime
		h = (h ^ uint64(k.dst[i])) * prime
	}
	return h
}

// newKey builds a lookup key from a flow.
func newKey(f *Flow) key {
	k := key{p: f.Proto, sp: f.SrcPort, dp: f.DstPort}
	copy(k.src[:], f.SrcIP[:])
	copy(k.dst[:], f.DstIP[:])
	return k
}

// Get returns the cached flow for k, ignoring TTL expiry.
func (t *Table) Get(k *key) (*Flow, bool) {
	sh, bi := t.sel(k)
	sh.mu.Lock()
	for e := sh.buckets[bi]; e != nil; e = e.next {
		if e.k == *k {
			e.f.Sampled = false
			e.f.Stats.FlowStart = sh.now()
			sh.mu.Unlock()
			t.hits.Add(1)
			return e.f, true
		}
	}
	sh.mu.Unlock()
	t.misses.Add(1)
	return nil, false
}

// Put stores a flow, returning the stored *Flow (the input if fresh).
func (t *Table) Put(f *Flow) *Flow {
	k := newKey(f)
	sh, bi := t.sel(&k)
	sh.mu.Lock()
	for e := sh.buckets[bi]; e != nil; e = e.next {
		if e.k == k {
			sh.mu.Unlock()
			return e.f // already exists
		}
	}
	id := t.next.Add(1)
	f.ID = id
	e := &entry{k: k, f: f, insert: sh.now()}
	e.next = sh.buckets[bi]
	sh.buckets[bi] = e
	t.active.Add(1)
	sh.mu.Unlock()
	return f
}

// UpdateBytes merges directional byte counters into an existing flow.
func (t *Table) UpdateBytes(k *key, up, down uint64, pUp, pDown uint64) {
	sh, bi := t.sel(k)
	sh.mu.Lock()
	for e := sh.buckets[bi]; e != nil; e = e.next {
		if e.k == *k {
			e.f.mu.Lock()
			e.f.BytesUpload += up
			e.f.BytesDownload += down
			e.f.PacketsUp += pUp
			e.f.PacketsDown += pDown
			e.f.mu.Unlock()
			break
		}
	}
	sh.mu.Unlock()
}

// LookupFlow returns the cached flow matching f's identity.
func (t *Table) LookupFlow(f *Flow) (*Flow, bool) {
	k := newKey(f)
	return t.Get(&k)
}

// InsertFlow registers f, returning the resident *Flow.
func (t *Table) InsertFlow(f *Flow) *Flow {
	return t.Put(f)
}

// UpdateFlow merges bytes/packets into an existing flow.
func (t *Table) UpdateFlow(f *Flow, up, down uint64, pUp, pDown uint64) {
	k := newKey(f)
	t.UpdateBytes(&k, up, down, pUp, pDown)
}

// Sweep removes expired flows. Returns how many were evicted.
func (t *Table) Sweep() int64 {
	var evicted int64
	now := time.Now()
	for _, sh := range t.shards {
		sh.mu.Lock()
		for bi := range sh.buckets {
			var prev *entry
			for e := sh.buckets[bi]; e != nil; {
				// Classified flows are re-evicted after the TTL. The previous
				// exclusion of f.Suspicious pinned every slow-path flow forever
				// (gateway.finish marks ALL slow-path flows Suspicious), which
				// caused unbounded memory growth. Sampled flows are still pinned.
				reap := now.Sub(e.insert) > sh.ttl && !e.f.Sampled
				if reap {
					if prev == nil {
						sh.buckets[bi] = e.next
					} else {
						prev.next = e.next
					}
					evicted++
					t.active.Add(-1)
				} else {
					prev = e
				}
				if prev != nil {
					e = prev.next
				} else {
					e = sh.buckets[bi]
				}
			}
		}
		sh.mu.Unlock()
	}
	return evicted
}
