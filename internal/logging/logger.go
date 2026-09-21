package logging

import (
	"strings"
	"sync/atomic"
	"time"

	"gfw-x/internal/metrics"
)

// Entry is a single structured log record.
type Entry = metrics.Event

// Storage writes batches of entries to a durable / queryable sink.
type Storage interface {
	WriteBatch(entries []*Entry) error
	Close() error
}

// degraded counters track overload shedding.
type Pipeline struct {
	queue       chan *Entry
	storage     Storage
	redact      bool
	sampleRatio float64 // 1.0 = keep all, <1 sampled

	writers   atomic.Uint64
	droppedA  atomic.Uint64 // full events shed (full metadata unavailable)
	droppedB  atomic.Uint64 // sampled events shed
	summaries atomic.Uint64 // events reduced to counters
	closed    atomic.Bool
	flushed   atomic.Uint64 // total events written by the drain goroutine (both loops)

	batchSize int
	batchWait time.Duration
	stop      chan struct{}
	done      chan struct{}
}

// NewPipeline builds an async log pipeline. queueCap is the bounded ingress
// channel. Drain runs WriteBatch batching up to batchSize events or batchWait.
func NewPipeline(q Storage, queueCap int, redact bool, sampleRatio float64) *Pipeline {
	if queueCap <= 0 {
		queueCap = 1024
	}
	p := &Pipeline{
		queue:       make(chan *Entry, queueCap),
		storage:     q,
		redact:      redact,
		sampleRatio: sampleRatio,
		batchSize:   512,
		batchWait:   200 * time.Millisecond,
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
	}
	go p.drain()
	return p
}

// Submit enqueues an event without blocking the data plane. When overloaded
// it degrades: full metadata → sampled metadata → counters only.
func (p *Pipeline) Submit(e *Entry) {
	if p.closed.Load() {
		return
	}
	e = p.sanitize(e)
	if p.sampleRatio < 1 && !sampleHit(p.sampleRatio) {
		p.droppedB.Add(1)
		return
	}
	select {
	case p.queue <- e:
		p.writers.Add(1)
	default:
		// queue full: reduce to counters only
		p.summaries.Add(1)
		p.droppedA.Add(1)
	}
}

func (p *Pipeline) drain() {
	buf := make([]*Entry, 0, p.batchSize)
	timer := time.NewTimer(p.batchWait)
	defer timer.Stop()
	for {
		select {
		case <-p.stop:
			// Graceful shutdown: Close has set `closed` (so no new Submit can
			// enqueue) then closed stop. Every event already accepted into the
			// queue must still be written, so drain until the number flushed
			// matches the accept counter — never leave a queued event behind.
			p.drainAll(buf)
			close(p.done) // signal Close that all writes are done
			return
		case e := <-p.queue:
			buf = append(buf, e)
			if len(buf) >= p.batchSize {
				p.flush(buf)
				buf = buf[:0]
				timer.Reset(p.batchWait)
			}
		case <-timer.C:
			if len(buf) > 0 {
				p.flush(buf)
				buf = buf[:0]
			}
			timer.Reset(p.batchWait)
		}
	}
}

// drainAll flushes every remaining accepted event. It compares the global
// flushed counter (all loops) against the writers counter (all successful
// enqueues), so events already flushed by the main drain loop before stop are
// counted too. It keeps draining until flushed_total >= writers and the queue
// stays idle for a few ticks (covering an in-flight producer that passed the
// closed check just before Close set stop). buf is consumed in place; any
// trailing partial batch is flushed on exit.
func (p *Pipeline) drainAll(buf []*Entry) {
	idle := 0
	for {
		consumed := false
		// Consume everything currently available in the queue.
	inner:
		for {
			select {
			case e := <-p.queue:
				consumed = true
				buf = append(buf, e)
				if len(buf) >= p.batchSize {
					p.flush(buf)
					buf = buf[:0]
				}
			default:
				break inner
			}
		}
		if consumed {
			idle = 0
		} else {
			idle++
		}
		// Every accepted event is accounted for by either an already-flushed
		// batch (flushed) or entries currently held in buf (written on exit).
		// writers increments only after a successful enqueue, so when the
		// accounted total reaches it and the queue stays idle for a few ticks
		// (covering an in-flight producer that passed the closed check just
		// before Close set stop), no accepted event is left behind.
		if idle >= 3 && p.flushed.Load()+uint64(len(buf)) >= p.writers.Load() {
			break
		}
		time.Sleep(50 * time.Microsecond)
	}
	p.flush(buf)
}

func (p *Pipeline) flush(buf []*Entry) {
	if len(buf) == 0 {
		return
	}
	_ = p.storage.WriteBatch(buf)
	p.flushed.Add(uint64(len(buf)))
}

// Close flushes remaining entries and shuts down the writer. It waits for the
// drain goroutine's final flush before closing the underlying storage so no
// batch is ever written to a closed sink.
func (p *Pipeline) Close() error {
	if p.closed.Swap(true) {
		return nil
	}
	close(p.stop)
	<-p.done // drain flushes synchronously, then signals
	return p.storage.Close()
}

// Stats returns shedding counters.
func (p *Pipeline) Stats() (written, droppedFull, droppedSampled, counters uint64) {
	return p.writers.Load(), p.droppedA.Load(), p.droppedB.Load(), p.summaries.Load()
}

func (p *Pipeline) sanitize(e *Entry) *Entry {
	if !p.redact {
		return e
	}
	out := *e
	// Never store payload (we never populate one). Mask the host portions of
	// both endpoints so stored logs do not leak exact addresses.
	out.Src = maskIP(out.Src)
	out.Dst = maskIP(out.Dst)
	return &out
}

// sampleHit is a cheap deterministic sampler.
func sampleHit(ratio float64) bool {
	if ratio >= 1 {
		return true
	}
	if ratio <= 0 {
		return false
	}
	return hashSample()/float64(1<<20) < ratio
}

// sampleSeed drives hashSample. It is a package-level counter written by many
// gateway worker goroutines, so it MUST be atomic to avoid a data race.
var sampleSeed atomic.Uint64

func hashSample() float64 {
	// rotate a counter; fine for sampling decisions.
	v := sampleSeed.Add(1) * 6364136223846793005
	return float64(v & ((1 << 20) - 1))
}

// maskIP masks the host-portion of an IPv4 (last octet -> 0) or IPv6 address
// (tail after the last ':' -> 0). Non-address strings are returned unchanged.
func maskIP(s string) string {
	if strings.Contains(s, ":") {
		if i := strings.LastIndex(s, ":"); i >= 0 {
			return s[:i+1] + "0"
		}
		return s
	}
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[:i+1] + "0"
	}
	return s
}
