//go:build linux

package nfq

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"gfw-x/internal/config"
	"gfw-x/internal/pipeline"
)

// This integration test exercises the real NFQUEUE netlink data plane against
// the kernel:
//
//	nftables (queue N) ─► NFQUEUE ─► Source.Next ─► verdict ─► ACCEPT/DROP
//
// It requires root (CAP_NET_ADMIN), the nft binary, and the nfnetlink_queue
// kernel module. It is intentionally gated behind GFWX_NFQUEUE_INTEGRATION=1
// so the normal `go test ./...` run never needs privileges.
//
//	GFWX_NFQUEUE_INTEGRATION=1 go test ./internal/nfq -run Integration
func TestNFQueueIntegration(t *testing.T) {
	if os.Getenv("GFWX_NFQUEUE_INTEGRATION") != "1" {
		t.Skip("GFWX_NFQUEUE_INTEGRATION not set; skipping root-gated NFQUEUE integration test")
	}
	if os.Geteuid() != 0 {
		t.Skip("NFQUEUE live integration: NOT RUN — requires root / CAP_NET_ADMIN")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("NFQUEUE live integration: NOT RUN — nft binary not found")
	}

	const table = "gfwx_test"

	if _, err := nft("add", "table", "inet", table); err != nil {
		t.Skipf("NFQUEUE live integration: NOT RUN — cannot create nft table (CAP_NET_ADMIN/module unavailable): %v", err)
	}
	t.Cleanup(func() { _, _ = nft("delete", "table", "inet", table) })

	// Chain hooks outbound traffic so a local UDP send reaches NFQUEUE.
	if _, err := nft("add", "chain", "inet", table, "out", "{", "type", "filter", "hook", "output", "priority", "0;", "}"); err != nil {
		t.Fatalf("add chain: %v", err)
	}
	// Send every IPv4 packet in that chain to NFQUEUE queue 501 (0x1F5).
	if _, err := nft("add", "rule", "inet", table, "out", "ip", "queue", "num", "501"); err != nil {
		t.Fatalf("add queue rule: %v", err)
	}

	cfg := config.NFQueueCfg{QueueNum: 501, MaxWorkers: 1, FailMode: "open"}
	src, err := NewSource(cfg)
	if err != nil {
		t.Skipf("NFQUEUE live integration: NOT RUN — openNFQueue failed (nfnetlink_queue module unavailable): %v", err)
	}
	t.Cleanup(func() { _ = src.Stop() })

	if err := src.Start(); err != nil {
		t.Fatalf("source start: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	got := make(chan *pipeline.Packet, 1)
	errCh := make(chan error, 1)
	go func() {
		p, err := src.Next(ctx)
		if err != nil {
			errCh <- err
			return
		}
		got <- p
	}()

	conn, err := net.Dial("udp4", "127.0.0.1:9")
	if err != nil {
		t.Skipf("NFQUEUE live integration: NOT RUN — cannot open UDP socket: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("gfwx-nfq-integration")); err != nil {
		t.Fatalf("send packet: %v", err)
	}

	var pkt *pipeline.Packet
	select {
	case p := <-got:
		pkt = p
	case err := <-errCh:
		t.Fatalf("Next errored: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for queued packet")
	}

	// The kernel always delivers an IPv4 header with a nonzero packet id.
	if len(pkt.Data) < 20 {
		t.Fatalf("queued packet too short: %d bytes", len(pkt.Data))
	}
	if v := pkt.Data[0] >> 4; v != 4 {
		t.Fatalf("expected IPv4, got IP version %d", v)
	}
	meta, ok := pkt.Meta.(Meta)
	if !ok {
		t.Fatalf("meta is %T, want Meta", pkt.Meta)
	}
	if meta.ID == 0 {
		t.Fatalf("packet id is 0")
	}

	sink, err := NewSink(src, "open", nil)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	if err := sink.Write(context.Background(), pkt, pipeline.Verdict("allow")); err != nil {
		t.Fatalf("accept verdict write: %v", err)
	}

	t.Logf("NFQUEUE integration: received %d-byte IPv4 frame, packet_id=%d, accepted", len(pkt.Data), meta.ID)
}

// nft runs the nft binary and returns combined output.
func nft(args ...string) (string, error) {
	out, err := exec.Command("nft", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
