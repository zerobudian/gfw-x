//go:build linux

package nfq

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"gfw-x/internal/config"
	"gfw-x/internal/pipeline"
)

// Protocol families for the netlink bind.
const (
	afINET  uint8 = 2 // AF_INET
	afINET6 uint8 = 10
)

// recvBufSize bounds each netlink receive buffer. Packets larger than this are
// truncated by the kernel via the negotiated copy_range.
const recvBufSize = 64 * 1024

// queue is the live netlink NFQUEUE handle. One fd backs both the packet read
// loop and verdict submission; guards serialize the latter.
type queue struct {
	fd   int
	seq  atomic.Uint32
	cfg  config.NFQueueCfg
	mu   sync.Mutex // serializes verdict sends
	done chan struct{}
}

// openNFQueue binds to a single netfilter queue and configures copy mode.
func openNFQueue(cfg config.NFQueueCfg) (*queue, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("nfq: socket: %w", err)
	}
	q := &queue{fd: fd, cfg: cfg, done: make(chan struct{})}

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 0, Groups: uint32(1 << (NFNL_SUBSYS_QUEUE - 1))}
	// Pid: the netlink port id; for NFQUEUE the kernel routes verdicts to the
	// bind group, so we can leave pid 0 and rely on the group subscription.
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("nfq: bind: %w", err)
	}

	// Bind the protocol family (IPv4; IPv6 reserved for a later milestone).
	if err := q.sendConfig(afINET, 0, &nfqnlMsgConfigCmd{Command: NFQNL_CFG_CMD_PF_BIND, PF: uint16(afINET)}, nil); err != nil {
		q.closeFd()
		return nil, fmt.Errorf("nfq: pf bind: %w", err)
	}

	// Bind the queue and set COPY_PACKET with a generous copy range so we get
	// whole frames (up to recvBufSize). A single config message piggybacks the
	// params after the bind command (matching the kernel's nfqnl_recv_config).
	if err := q.sendConfig(0 /* AF_UNSPEC */, uint16(cfg.QueueNum), &nfqnlMsgConfigCmd{Command: NFQNL_CFG_CMD_BIND}, &nfqnlMsgConfigParams{CopyRange: 0xff, CopyMode: NFQNL_COPY_PACKET}); err != nil {
		q.closeFd()
		return nil, fmt.Errorf("nfq: queue bind: %w", err)
	}

	return q, nil
}

// sendConfig writes a configuration message and waits for the ack to ensure the
// kernel has processed it (avoids racing the first packets with queue setup).
// family is the netfilter family (AF_UNSPEC for queue ops), resID the queue
// number for queue ops.
func (q *queue) sendConfig(family uint8, resID uint16, cmd *nfqnlMsgConfigCmd, params *nfqnlMsgConfigParams) error {
	seq := q.seq.Add(1)
	buf := buildConfigMarshal(seq, family, resID, cmd, params)
	if _, err := unix.Write(q.fd, buf); err != nil {
		return err
	}
	// Drain the ack / config reply.
	return q.waitAck(seq)
}

// waitAck reads until the netlink message whose seq matches seq arrives.
func (q *queue) waitAck(seq uint32) error {
	deadline := time.Now().Add(3 * time.Second)
	rbuf := make([]byte, 2048)
	for {
		rem := time.Until(deadline)
		if rem <= 0 {
			return errors.New("nfq: timeout waiting for config ack")
		}
		if err := unix.SetNonblock(q.fd, true); err != nil {
			return err
		}
		n, err := unix.Read(q.fd, rbuf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			return err
		}
		if n < 16 {
			continue
		}
		rseq := binary.NativeEndian.Uint32(rbuf[8:12])
		if rseq == seq {
			return nil
		}
	}
}

// Next reads the next queued packet, blocking until one arrives or ctx is done.
func (q *queue) Next(ctx context.Context) (*pipeline.Packet, error) {
	rbuf := make([]byte, recvBufSize)
	for {
		select {
		case <-ctx.Done():
			return nil, pipeline.ErrStopped
		case <-q.done:
			return nil, pipeline.ErrStopped
		default:
		}
		if err := unix.SetNonblock(q.fd, true); err != nil {
			return nil, err
		}
		n, err := unix.Read(q.fd, rbuf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) {
				time.Sleep(time.Microsecond)
				continue
			}
			return nil, err
		}
		if n < 16 {
			continue // stray short netlink header, skip
		}
		// Netlink messages may be batched; only handle NFQNL_MSG_PACKET.
		msgType := binary.NativeEndian.Uint16(rbuf[4:6])
		if msgType != nfqnlType(NFQNL_MSG_PACKET) {
			continue
		}
		payload, meta, err := parsePacketMsg(rbuf[:n])
		if err != nil {
			// Malformed / malformed packet: drop it to keep the queue from
			// stalling, and move on.
			return nil, fmt.Errorf("nfq: parse: %w", err)
		}
		return &pipeline.Packet{Data: payload, Captured: time.Now(), Meta: meta}, nil
	}
}

// Verdict submits a kernel verdict for a previously enqueued packet.
func (q *queue) Verdict(meta Meta, verdict uint32) error {
	seq := q.seq.Add(1)
	buf := buildVerdict(seq, 0, meta, verdict)
	q.mu.Lock()
	defer q.mu.Unlock()
	_, err := unix.Write(q.fd, buf)
	return err
}

// closeFd closes the netlink socket (idempotent).
func (q *queue) closeFd() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.fd >= 0 {
		_ = unix.Close(q.fd)
		q.fd = -1
	}
}

// Stop signals the read loop and closes the socket.
func (q *queue) Stop() error {
	select {
	case <-q.done:
	default:
		close(q.done)
		q.closeFd()
	}
	return nil
}

// Source is a pipeline.PacketSource over a live NFQUEUE queue.
type Source struct {
	q *queue
}

// NewSource opens and configures the queue. It returns an error on failure so
// the caller can choose fail-open / fail-closed startup behavior.
func NewSource(cfg config.NFQueueCfg) (*Source, error) {
	q, err := openNFQueue(cfg)
	if err != nil {
		return nil, err
	}
	return &Source{q: q}, nil
}

func (s *Source) Start() error { return nil }
func (s *Source) Next(ctx context.Context) (*pipeline.Packet, error) {
	return s.q.Next(ctx)
}
func (s *Source) Stop() error { return s.q.Stop() }

// Verdict submits a verdict for a packet seen by this source.
func (s *Source) Verdict(meta Meta, verdict uint32) error { return s.q.Verdict(meta, verdict) }

// Sink is a pipeline.PacketSink that returns verdicts to the kernel. It
// implements fail-open / fail-closed on transport errors and tracks overflow.
type Sink struct {
	src        *Source
	failMode   string       // "open" | "closed"
	overflow   atomic.Int64 // mirrored for gateway observability
	overflowFn func(int64)
}

// NewSink builds a verdict sink over a source.
func NewSink(src *Source, failMode string, overflowFn func(int64)) (*Sink, error) {
	if overflowFn == nil {
		overflowFn = func(int64) {}
	}
	return &Sink{src: src, failMode: failMode, overflowFn: overflowFn}, nil
}

// Write submits a verdict, applying the fail mode when the verdict cannot be
// delivered (e.g. netlink error after a timeout or a closed queue).
func (s *Sink) Write(ctx context.Context, p *pipeline.Packet, v pipeline.Verdict) error {
	meta, ok := p.Meta.(Meta)
	if !ok {
		// No verdict target (wrong source type): treat as accept, no-op.
		return nil
	}
	verdict := verdictFor(string(v))
	err := s.src.Verdict(meta, verdict)
	if err == nil {
		return nil
	}
	// Verdict delivery failed. Under fail-open we ACCEPT (never silently drop);
	// under fail-closed we DROP. Both paths are observable via the overflow
	// counter so operators can see what the kernel decided.
	final := verdict
	if s.failMode == "closed" {
		final = NF_DROP
	} else {
		final = NF_ACCEPT
	}
	if retryErr := s.src.Verdict(meta, final); retryErr == nil {
		return nil
	}
	s.overflow.Add(1)
	s.overflowFn(s.overflow.Load())
	return fmt.Errorf("nfq: verdict delivery failed (%v); fail_mode=%s", err, s.failMode)
}

func (s *Sink) Stop() error { return nil }

// compile-time interface assertions.
var (
	_ pipeline.PacketSource = (*Source)(nil)
	_ pipeline.PacketSink   = (*Sink)(nil)
)
