package integration

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gfw-x/internal/config"
	"gfw-x/internal/gateway"
)

// TestRuleHotReload verifies the atomic repo swap under concurrent traffic:
// no data race, no panic, no half-old/half-new decision, existing flows keep
// their cached decision, and new flows observe the swapped rule set.
func TestRuleHotReload(t *testing.T) {
	gw, m, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
	defer cleanup()

	feed := func(srcPort uint16, sni string) {
		gw.Ingest(&gateway.Traffic{
			SrcIP: "10.0.0.30", DstIP: "93.184.216.34",
			SrcPort: srcPort, DstPort: 443,
			Transport: "tcp", Sample: clientHello(0x0303, sni, true),
			UpBytes: 128, DownBytes: 300,
		})
	}

	// Establish a stable existing flow that will be cached as BLOCK.
	feed(50001, "example.com")
	waitFor(t, 3*time.Second, func() bool { return m.C.Blocked.Load() == 1 }, "existing flow block")

	allowRepo := mustRepo(t, "ALLOW example.com\n")
	blockRepo := mustRepo(t, "BLOCK example.com\n")

	// Fresh source port source for collision-free distinct flows.
	var srcPort atomic.Uint64
	srcPort.Store(60000)

	// Concurrent load: swapper toggles the repo while traffic keeps flowing.
	var wg sync.WaitGroup
	swapper := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-swapper:
				return
			default:
				if i%2 == 0 {
					gw.SetActiveRepo(allowRepo)
				} else {
					gw.SetActiveRepo(blockRepo)
				}
				i++
			}
		}
	}()

	traffic := func() {
		defer wg.Done()
		for i := 0; i < 400; i++ {
			sni := "example.com"
			if i%2 == 0 {
				sni = "cloudflare.com"
			}
			gw.Ingest(&gateway.Traffic{
				SrcIP: "10.0.0.31", DstIP: "93.184.216.34",
				SrcPort: uint16(srcPort.Add(1)), DstPort: 443,
				Transport: "tcp", Sample: clientHello(0x0303, sni, true),
				UpBytes: 128, DownBytes: 300,
			})
		}
	}
	wg.Add(3)
	go traffic()
	go traffic()
	go traffic()

	time.Sleep(300 * time.Millisecond)
	close(swapper)
	wg.Wait()

	// No panic reached here. Some traffic must have been classified.
	if m.C.Decisions.Load() == 0 {
		t.Fatal("concurrent reload produced no decisions")
	}

	// Now pin the ALLOW rule set and confirm NEW flows are allowed (not blocked).
	gw.SetActiveRepo(allowRepo)
	beforeAllowed := m.C.Allowed.Load()
	feed(50002, "example.com")
	waitFor(t, 3*time.Second, func() bool { return m.C.Allowed.Load() == beforeAllowed+1 }, "new flow allowed")
}

// TestRuleHotReloadExistingFlowKeepsDecision confirms that once a flow is
// classified under the old rule set, its cached decision survives a swap.
func TestRuleHotReloadExistingFlowKeepsDecision(t *testing.T) {
	gw, m, cleanup := newGateway(t, config.ModeBlock, "BLOCK example.com\n")
	defer cleanup()

	gw.Ingest(&gateway.Traffic{
		SrcIP: "10.0.0.40", DstIP: "93.184.216.34",
		SrcPort: 51001, DstPort: 443,
		Transport: "tcp", Sample: clientHello(0x0303, "example.com", true),
		UpBytes: 128, DownBytes: 300,
	})
	waitFor(t, 3*time.Second, func() bool { return m.C.Blocked.Load() >= 1 }, "block cached")

	// Swap to allow.
	gw.SetActiveRepo(mustRepo(t, "ALLOW example.com\n"))

	// Re-ingest the SAME 5-tuple: fast path serves the cached block decision.
	before := m.C.Blocked.Load()
	gw.Ingest(&gateway.Traffic{
		SrcIP: "10.0.0.40", DstIP: "93.184.216.34",
		SrcPort: 51001, DstPort: 443,
		Transport: "tcp", Sample: clientHello(0x0303, "example.com", true),
		UpBytes: 128, DownBytes: 300,
	})
	waitFor(t, 3*time.Second, func() bool { return m.C.Blocked.Load() == before+1 }, "existing flow keeps block")

	// A completely fresh flow with the new rule must be allowed instead.
	b := m.C.Blocked.Load()
	gw.Ingest(&gateway.Traffic{
		SrcIP: "10.0.0.40", DstIP: "93.184.216.34",
		SrcPort: 51002, DstPort: 443,
		Transport: "tcp", Sample: clientHello(0x0303, "example.com", true),
		UpBytes: 128, DownBytes: 300,
	})
	time.Sleep(150 * time.Millisecond)
	if m.C.Blocked.Load() != b {
		t.Fatalf("new flow must not be blocked after swap to allow, blocked=%d", m.C.Blocked.Load())
	}
	if m.C.Allowed.Load() == 0 {
		t.Fatal("new flow should be counted as allowed after swap")
	}
}
