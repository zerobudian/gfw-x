package integration

import (
	"sync"
	"testing"
	"time"

	"gfw-x/internal/config"
	"gfw-x/internal/detect"
	"gfw-x/internal/dpi"
	"gfw-x/internal/gateway"
	"gfw-x/internal/logging"
	"gfw-x/internal/metrics"
)

// trackingStorage records everything written and flags any write after the
// sink has been closed, so the shutdown test can prove no data loss and no
// write-after-close.
type trackingStorage struct {
	mu             sync.Mutex
	entries        []*logging.Entry
	wroteAfterDone bool
	closed         bool
	closeCalls     int
}

func (s *trackingStorage) WriteBatch(es []*logging.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		s.wroteAfterDone = true
	}
	s.entries = append(s.entries, es...)
	return nil
}

func (s *trackingStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.closeCalls++
	return nil
}

func (s *trackingStorage) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// TestShutdown_PipelineDrainsWithoutLoss verifies that every entry accepted
// into the pipeline before Close is flushed to storage, and that no further
// writes happen after Close. Accepted count is tracked by the pipeline's own
// writers counter (events actually enqueued; overload shedding may drop some).
func TestShutdown_PipelineDrainsWithoutLoss(t *testing.T) {
	t.Run("non_overload_exact", func(t *testing.T) {
		store := &trackingStorage{}
		pipe := logging.NewPipeline(store, 4096, false, 1.0)
		const n = 50
		for i := 0; i < n; i++ {
			pipe.Submit(&metrics.Event{ID: uint64(1000 + i), Domain: "example.com", Action: "block"})
		}
		if err := pipe.Close(); err != nil {
			t.Fatalf("pipeline close: %v", err)
		}
		if got := store.count(); got != n {
			t.Fatalf("non-overload drain lost accepted entries: stored=%d want=%d", got, n)
		}
		if store.wroteAfterDone {
			t.Fatal("storage was written after Close")
		}
		if store.closeCalls != 1 {
			t.Fatalf("storage.Close must be called exactly once, got %d", store.closeCalls)
		}
	})

	t.Run("overload_bounded", func(t *testing.T) {
		store := &trackingStorage{}
		pipe := logging.NewPipeline(store, 128, false, 1.0)
		const n = 5000
		for i := 0; i < n; i++ {
			pipe.Submit(&metrics.Event{ID: uint64(2000 + i), Domain: "example.com", Action: "block"})
		}
		if err := pipe.Close(); err != nil {
			t.Fatalf("pipeline close: %v", err)
		}
		writers, _, _, _ := pipe.Stats()
		// Every event that entered the queue must be flushed.
		if got := store.count(); got != int(writers) {
			t.Fatalf("overload drain lost accepted entries: stored=%d accepted(writers)=%d", got, writers)
		}
		if store.count() > n {
			t.Fatalf("stored more events than submitted: %d > %d", store.count(), n)
		}
		if store.wroteAfterDone {
			t.Fatal("storage was written after Close")
		}
	})

	t.Run("submit_after_close_noop", func(t *testing.T) {
		store := &trackingStorage{}
		pipe := logging.NewPipeline(store, 128, false, 1.0)
		pipe.Submit(&metrics.Event{ID: 1, Domain: "a", Action: "block"})
		if err := pipe.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		before := store.count()
		pipe.Submit(&metrics.Event{ID: 999, Domain: "late", Action: "block"})
		if store.count() != before {
			t.Fatalf("write after Close must be blocked, stored=%d want=%d", store.count(), before)
		}
	})
}

// TestShutdown_GatewayCoherent verifies orderly shutdown of a live gateway
// while traffic is flowing and logs are queued: stop is prompt, pending
// emitted events all reach storage, and the sink is never written after close.
// Run under -race to catch goroutine leaks / data races.
func TestShutdown_GatewayCoherent(t *testing.T) {
	cfg := newConfig(config.ModeBlock)
	repo := mustRepo(t, "BLOCK example.com\n")
	m := metrics.New(8192)
	store := &trackingStorage{}
	pipe := logging.NewPipeline(store, 4096, false, 1.0)
	det := detect.NewEngine(false, 0.85, false)
	dpiEng := dpi.NewEngine(true, 0.0)
	gw := gateway.New(cfg, repo, m, pipe, det, dpiEng)
	gw.Start()

	// Concurrent traffic keeps active flows + queued logs alive.
	var wg sync.WaitGroup
	wg.Add(2)
	stopTraffic := make(chan struct{})
	spawn := func(basePort uint16) {
		defer wg.Done()
		port := basePort
		for {
			select {
			case <-stopTraffic:
				return
			default:
				port++
				gw.Ingest(&gateway.Traffic{
					SrcIP: "10.0.0.1", DstIP: "93.184.216.34",
					SrcPort: port, DstPort: 443,
					Transport: "tcp", Sample: clientHello(0x0303, "example.com", true),
					UpBytes: 128, DownBytes: 256,
				})
				time.Sleep(time.Millisecond)
			}
		}
	}
	go spawn(40000)
	go spawn(41000)

	// Let traffic classify and queue logs.
	waitFor(t, 3*time.Second, func() bool { return m.C.Blocked.Load() >= 5 }, "traffic classified")
	close(stopTraffic)
	wg.Wait()

	// Prudent pause so the drain goroutine moves the last emitted events.
	time.Sleep(50 * time.Millisecond)

	// Graceful shutdown: stop workers, then drain + close logging.
	gw.Stop()
	done := make(chan struct{})
	go func() { _ = pipe.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown deadlocked: Close did not return")
	}

	flushed := waitForResult(3*time.Second, func() bool {
		evs := m.Events()
		return store.count() >= len(evs) && store.count() > 0
	})
	if !flushed {
		evs := m.Events()
		t.Fatalf("no data loss expected: stored=%d registryEvents=%d", store.count(), len(evs))
	}
	if store.wroteAfterDone {
		t.Fatal("storage written after Close during gateway shutdown")
	}
}

func waitForResult(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}
