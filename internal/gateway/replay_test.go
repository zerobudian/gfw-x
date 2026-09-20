package gateway

import (
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"gfw-x/internal/config"
	"gfw-x/internal/detect"
	"gfw-x/internal/dpi"
	"gfw-x/internal/logging"
	"gfw-x/internal/metrics"
	"gfw-x/internal/rules"
)

// TestReplayIngestsUDPFrame verifies the offline .pcap replay path: a classic
// .pcap holding a single Ethernet/IPv4/UDP frame must be decoded and fed into
// the gateway data-plane (Counters.Packets increments).
func TestReplayIngestsUDPFrame(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "sample.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(f.Name()) }()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	frame := buildUDPFrame()
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(0, 0), CaptureLength: len(frame), Length: len(frame)}, frame); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	g := newReplayTestGateway(t)
	r := NewReplay(g, f.Name(), 0)
	r.Start()
	defer r.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && g.m.C.Packets.Load() == 0 {
		time.Sleep(2 * time.Millisecond)
	}
	if n := g.m.C.Packets.Load(); n == 0 {
		t.Fatalf("expected >=1 ingested packet from replay, got 0")
	} else {
		t.Logf("replay ingested %d packet(s)", n)
	}
}

func newReplayTestGateway(t *testing.T) *Gateway {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Default.Mode = config.ModeBlock
	cfg.Runtime.WorkerPool = 2
	cfg.Runtime.ChannelCapacity = 1024
	cfg.Runtime.FlowTTL = 30

	rs, err := rules.ParseBytes([]byte("BLOCK example.com\n"), "txt")
	if err != nil {
		t.Fatal(err)
	}
	repo := rules.NewRepo()
	repo.Replace(rs)

	m := metrics.New(256)
	lg := logging.NewPipeline(logging.RingStorage{}, 1024, true, 1.0)
	det := detect.NewEngine(true, 0.85, false)
	dp := dpi.NewEngine(true, 0.02)
	g := New(cfg, repo, m, lg, det, dp)
	g.Start()
	t.Cleanup(g.Stop)
	return g
}

// buildUDPFrame returns an Ethernet+IPv4+UDP frame (DNS query heading to :53).
func buildUDPFrame() []byte {
	return []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // dst MAC
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, // src MAC
		0x08, 0x00, // EtherType IPv4
		// IPv4 header (id=0, ttl=64, proto=UDP, no checksum)
		0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
		192, 168, 0, 1, 8, 8, 8, 8,
		// UDP header (sport 12345=0x3039, dport 53=0x0035, len 8)
		0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
	}
}