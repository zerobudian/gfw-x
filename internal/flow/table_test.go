package flow

import (
	"fmt"
	"net"
	"testing"
	"time"
)

func bytesIP(s string) [16]byte {
	var out [16]byte
	copy(out[:], net.ParseIP(s).To16())
	return out
}

func testFlow(i int) *Flow {
	return &Flow{
		ID:      uint64(i),
		Proto:   ProtoTCP,
		SrcIP:   bytesIP(fmt.Sprintf("10.0.%d.%d", i%200, i%255)),
		DstIP:   bytesIP("203.0.113.5"),
		SrcPort: uint16(49000 + i%1000),
		DstPort: 443,
	}
}

func TestTableInsertLookup(t *testing.T) {
	tbl := NewTable(16, time.Minute)
	f := testFlow(1)
	got := tbl.InsertFlow(f)
	if got != f {
		t.Fatal("InsertFlow should return same flow")
	}
	k := newKey(f)
	cached, ok := tbl.Get(&k)
	if !ok || cached != f {
		t.Fatal("Get should return the inserted flow in fast path cache")
	}
	if tbl.ActiveFlows() != 1 {
		t.Fatalf("active=%d want 1", tbl.ActiveFlows())
	}
	tbl.UpdateFlow(f, 100, 200, 1, 2)
	if tbl.LookupHits() < 1 {
		t.Fatalf("expected lookup hits, got %d", tbl.LookupHits())
	}
}

func TestTableSweepExpires(t *testing.T) {
	tbl := NewTable(8, 50*time.Millisecond)
	tbl.InsertFlow(testFlow(1))
	if tbl.ActiveFlows() != 1 {
		t.Fatal("flow not inserted")
	}
	time.Sleep(80 * time.Millisecond)
	if removed := tbl.Sweep(); removed != 1 {
		t.Fatalf("sweep removed=%d want 1", removed)
	}
	if tbl.ActiveFlows() != 0 {
		t.Fatalf("active after sweep=%d want 0", tbl.ActiveFlows())
	}
}

// ----- benchmarks -----

func BenchmarkFlowTableInsert(b *testing.B) {
	tbl := NewTable(32, time.Minute)
	flows := make([]*Flow, 1000)
	for i := range flows {
		flows[i] = testFlow(i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tbl.InsertFlow(flows[i%len(flows)])
	}
}

func BenchmarkFlowTableLookup(b *testing.B) {
	tbl := NewTable(32, time.Minute)
	var keys []key
	for i := 0; i < 1000; i++ {
		f := testFlow(i)
		tbl.InsertFlow(f)
		keys = append(keys, newKey(f))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tbl.Get(&keys[i%len(keys)])
	}
}
