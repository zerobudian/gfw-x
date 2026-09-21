// Package pipeline defines the unified data-plane abstraction shared by every
// ingress source (PCAP replay, NFQUEUE, future AF_XDP). The processing chain is:
//
//	PacketSource → Decode → Flow Tracking → Metadata/DPI → Policy → Verdict → PacketSink
//
// Linux-specific packet sources live in self-contained packages (internal/nfq)
// and are plugged in here via the same interface, so the core policy engine and
// detector never depend on provider-specific packet I/O.
package pipeline

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

// Errors returned by sources / sinks.
var (
	ErrSourceClosed = errors.New("pipeline: source closed")
	ErrSinkClosed   = errors.New("pipeline: sink closed")
	ErrStopped      = errors.New("pipeline: stopped")
)

// Verdict is the disposition the data plane applied to a packet.
type Verdict string

// Packet is one captured frame entering the data plane. Decode extracts the
// normalized L3/L4 identity; the flow engine, detector and policy only ever
// see the decoded form, never raw provider formats.
type Packet struct {
	Data     []byte
	Captured time.Time
	Link     layers.LinkType
	// Meta is provider-specific context carried from Next through the sink.
	// NFQUEUE uses it to hold the kernel packet id + queue number needed to
	// submit a verdict. Leave nil for sources without a verdict target.
	Meta any
}

// PacketSource yields captured packets. Implementations must be safe to Stop
// concurrently and must not leak goroutines (Close joins all spawned workers).
type PacketSource interface {
	// Start opens the source (acquiring the live queue / opening the pcap).
	Start() error
	// Next blocks until a packet is available or the context is cancelled.
	// It returns io.EOF when the source is exhausted (offline) and
	// ErrStopped after Stop().
	Next(ctx context.Context) (*Packet, error)
	// Stop halts the source and joins worker goroutines.
	Stop() error
}

// PacketSink consumes the verdict produced for a packet, e.g. writing the
// verdict back to the kernel NFQUEUE verdict socket.
type PacketSink interface {
	Write(ctx context.Context, p *Packet, v Verdict) error
	Stop() error
}

// Processor decodes and classifies one packet into a Verdict.
type Processor func(ctx context.Context, p *Packet) (Verdict, error)

// SinkFunc adapts a plain function into a PacketSink.
type SinkFunc func(ctx context.Context, p *Packet, v Verdict) error

func (f SinkFunc) Write(ctx context.Context, p *Packet, v Verdict) error { return f(ctx, p, v) }

// NoopSink discards verdicts (used by PCAP replay, which has no kernel to
// enforce against).
func (f SinkFunc) Stop() error { return nil }

// Runner drives a PacketSource through a Processor into a PacketSink with a
// fixed worker pool. The number of goroutines is bounded by workers; when the
// source outpaces the pool, Next blocks (natural backpressure) so we never
// queue unboundedly.
type Runner struct {
	src     PacketSource
	proc    Processor
	sink    PacketSink
	workers int

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	errMu  sync.Mutex
	err    error
	wg     sync.WaitGroup
	once   sync.Once
}

// NewRunner builds a runner. workers must be >= 1.
func NewRunner(src PacketSource, proc Processor, sink PacketSink, workers int) *Runner {
	if workers < 1 {
		workers = 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Runner{
		src: src, proc: proc, sink: sink, workers: workers,
		ctx: ctx, cancel: cancel, done: make(chan struct{}),
	}
}

// Run starts the worker pool and blocks until the source is exhausted, an
// unrecoverable error occurs, or ctx is cancelled. It returns the first error
// encountered (io.EOF is treated as a clean shutdown and returns nil).
func (r *Runner) Run() error {
	if err := r.src.Start(); err != nil {
		return err
	}
	r.wg.Add(r.workers)
	for i := 0; i < r.workers; i++ {
		go r.worker()
	}
	<-r.done
	r.wg.Wait()
	r.src.Stop()
	r.errMu.Lock()
	defer r.errMu.Unlock()
	if r.err == io.EOF {
		return nil
	}
	return r.err
}

func (r *Runner) worker() {
	defer r.wg.Done()
	for {
		select {
		case <-r.ctx.Done():
			r.setErr(ErrStopped)
			return
		default:
		}
		pkt, err := r.src.Next(r.ctx)
		if err != nil {
			if err == io.EOF {
				r.setErr(io.EOF)
			} else if err != ErrStopped {
				r.setErr(err)
			}
			r.stopOnce()
			return
		}
		v, err := r.proc(r.ctx, pkt)
		if err != nil {
			r.setErr(err)
			r.stopOnce()
			return
		}
		if r.sink != nil {
			if err := r.sink.Write(r.ctx, pkt, v); err != nil {
				r.setErr(err)
				r.stopOnce()
				return
			}
		}
	}
}

// Stop cancels the runner and waits for workers to exit.
func (r *Runner) Stop() { r.cancel() }

func (r *Runner) setErr(err error) {
	r.errMu.Lock()
	if r.err == nil {
		r.err = err
	}
	r.errMu.Unlock()
}

func (r *Runner) stopOnce() {
	r.once.Do(func() {
		r.cancel()
		close(r.done)
	})
}
