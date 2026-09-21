package gateway

import (
	"sync"
	"testing"
	"time"

	"gfw-x/internal/config"
	"gfw-x/internal/detect"
	"gfw-x/internal/dpi"
	"gfw-x/internal/logging"
	"gfw-x/internal/metrics"
	"gfw-x/internal/rules"
)

func baseConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Default.Mode = config.ModeBlock
	cfg.Runtime.WorkerPool = 2
	cfg.Runtime.ChannelCapacity = 1024
	cfg.Runtime.FlowTTL = 30
	return cfg
}

func makeRepo(t *testing.T, lines string) *rules.RuleRepo {
	t.Helper()
	rs, err := rules.ParseBytes([]byte(lines), "txt")
	if err != nil {
		t.Fatalf("parse rules: %v", err)
	}
	repo := rules.NewRepo()
	repo.Replace(rs)
	return repo
}

// TestSetActiveRepoConcurrentWithWorkers drives SetActiveRepo from one goroutine
// while workers classify traffic through finish(). Before BUG-009 was fixed,
// g.pol/g.repo were plain pointers swapped without synchronization, so this
// test races under -race. It must now pass clean.
func TestSetActiveRepoConcurrentWithWorkers(t *testing.T) {
	cfg := baseConfig(t)
	repoA := makeRepo(t, "BLOCK example.com\n")
	repoB := makeRepo(t, "ALLOW example.com\nBLOCK *.pages.dev\n")

	m := metrics.New(256)
	lg := logging.NewPipeline(logging.RingStorage{}, 1024, true, 1.0)
	det := detect.NewEngine(true, 0.85, false)
	dp := dpi.NewEngine(true, 0.02)
	g := New(cfg, repoA, m, lg, det, dp)
	g.Start()

	const swaps = 300
	var swg sync.WaitGroup
	swg.Add(1)
	go func() {
		defer swg.Done()
		for i := 0; i < swaps; i++ {
			if i%2 == 0 {
				g.SetActiveRepo(repoA)
			} else {
				g.SetActiveRepo(repoB)
			}
		}
	}()

	// Feed distinct flows so every Ingest lands in a worker's finish().
	for i := 0; i < 2000; i++ {
		g.Ingest(&Traffic{
			SrcIP: "10.0.0.1", DstIP: "1.2.3.4",
			SrcPort: 40000 + uint16(i%1000), DstPort: 443,
			Transport: "udp", Category: "",
			Sample:  []byte{0x16, 0x03, 0x01}, // non-empty to force classification
			UpBytes: 64, DownBytes: 64,
		})
	}
	swg.Wait()

	g.Stop()
	<-time.After(50 * time.Millisecond) // allow workers to drain
	if err := lg.Close(); err != nil {
		t.Fatalf("logger close: %v", err)
	}
}
