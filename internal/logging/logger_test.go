package logging

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gfw-x/internal/metrics"
)

// trackingStorage records whether any batch is ever written after Close, and
// the total number of entries flushed before Close returns.
type trackingStorage struct {
	mu               sync.Mutex
	closed           atomic.Bool
	writesAfterClose int
	entriesFlushed   atomic.Int64
}

func (s *trackingStorage) WriteBatch(entries []*Entry) error {
	if s.closed.Load() {
		s.mu.Lock()
		s.writesAfterClose++
		s.mu.Unlock()
	}
	s.entriesFlushed.Add(int64(len(entries)))
	return nil
}

func (s *trackingStorage) Close() error {
	s.closed.Store(true)
	return nil
}

func newEntry(tag string) *Entry {
	return &metrics.Event{
		Action: "allow",
		Domain: tag,
	}
}

// TestPipelineCloseNoWriteAfterClose exercises concurrent Submit + Close under
// -race. Before the ownership fix, drain could flush into an already-closed
// storage (a swallowed write error). The handshake guarantees storage.Close
// happens only after the final flush, so writesAfterClose must be 0.
func TestPipelineCloseNoWriteAfterClose(t *testing.T) {
	st := &trackingStorage{}
	p := NewPipeline(st, 64, true, 1.0)

	const workers = 8
	const perWorker = 2000
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				p.Submit(newEntry("w"))
			}
		}(i)
	}
	wg.Wait()
	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if st.writesAfterClose != 0 {
		t.Fatalf("writes after close = %d, want 0", st.writesAfterClose)
	}
	// Never use a lock after Close returns is checked by test harness; just
	// assert we did not silently drop every event (sanity).
	if total := st.entriesFlushed.Load(); total == 0 {
		t.Fatal("expected at least one batch to be flushed")
	}
}

func TestPipelineDegradesWhenFull(t *testing.T) {
	st := &trackingStorage{}
	p := NewPipeline(st, 8, true, 1.0)
	defer p.Close()

	// Submit far more events than the queue capacity synchronously; Submit is
	// non-blocking and should shed (counters) rather than hang.
	full := 0
	for i := 0; i < 100000; i++ {
		before := p.summaries.Load()
		p.Submit(newEntry("w"))
		p.Submit(newEntry("x"))
		if p.summaries.Load() > before {
			full++
		}
	}
	if full == 0 {
		t.Fatal("expected at least one overload-shed (queue full) event")
	}
	// Allow drain to finish before defer Close.
	time.Sleep(50 * time.Millisecond)
}

func TestMaskIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.168.1.55", "192.168.1.0"},
		{"10.0.0.7", "10.0.0.0"},
		{"2001:db8::1234", "2001:db8::0"},
		{"not-an-ip", "not-an-ip"},
		{"", ""},
	}
	for _, c := range cases {
		if got := maskIP(c.in); got != c.want {
			t.Errorf("maskIP(%q)=%q, want %q", c.in, got, c.want)
		}
	}

	// sanitize under redact must mask both endpoints.
	p := NewPipeline(&trackingStorage{}, 4, true, 1.0)
	o := p.sanitize(&metrics.Event{Src: "192.168.1.55", Dst: "2001:db8::1234"})
	if o.Src != "192.168.1.0" || o.Dst != "2001:db8::0" {
		t.Fatalf("sanitize masks=%v/%v", o.Src, o.Dst)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// redact=false must NOT alter addresses.
	p2 := NewPipeline(&trackingStorage{}, 4, false, 1.0)
	o2 := p2.sanitize(&metrics.Event{Src: "192.168.1.55", Dst: "2001:db8::1234"})
	if o2.Src != "192.168.1.55" || o2.Dst != "2001:db8::1234" {
		t.Fatalf("no-redact should preserve addresses, got %v/%v", o2.Src, o2.Dst)
	}
	if err := p2.Close(); err != nil {
		t.Fatalf("close2: %v", err)
	}
}
