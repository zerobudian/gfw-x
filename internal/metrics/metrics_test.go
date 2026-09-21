package metrics

import "testing"

func TestThroughputAndCounters(t *testing.T) {
	r := New(256)
	r.AddBytes(1_000_000, 2_000_000)
	if r.Snapshot().BytesUp != 1_000_000 || r.Snapshot().BytesDown != 2_000_000 {
		t.Fatal("byte counters wrong")
	}
	if r.Throughput() <= 0 {
		t.Fatal("throughput should be >0 after adding bytes")
	}
}

func TestEventsBounded(t *testing.T) {
	r := New(64)
	for i := 0; i < 200; i++ {
		r.PushEvent(&Event{ID: uint64(i), Domain: "x.com", Action: "allow"})
	}
	evs := r.Events()
	if len(evs) > 64 {
		t.Fatalf("event ring not bounded: %d", len(evs))
	}
	// newest first
	if evs[0].ID != 199 {
		t.Fatalf("expected newest event id 199, got %d", evs[0].ID)
	}
}

func TestRanks(t *testing.T) {
	r := New(16)
	for _, d := range []string{"a.com", "b.com", "a.com", "c.com", "a.com"} {
		r.RecordTopDomain(d)
	}
	top := r.TopDomains(1)
	if len(top) != 1 || top[0].Key != "a.com" || top[0].Count != 3 {
		t.Fatalf("top domains wrong: %+v", top)
	}
}

func BenchmarkPushEvent(b *testing.B) {
	r := New(4096)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r.PushEvent(&Event{Domain: "github.com", Action: "allow", Dst: "127.0.0.1"})
	}
}
