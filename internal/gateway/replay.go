package gateway

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket/pcapgo"

	"gfw-x/internal/pipeline"
)

// Replay is a real-traffic input that reads a classic .pcap capture and feeds
// each captured packet into the data-plane as Traffic. Unlike the synthetic
// generator this drives the pipeline with genuine packet bytes (DNS query and
// TLS ClientHello samples included), so policy decisions reflect real traffic.
//
// It is pure-Go (gopacket/pcapgo, offline) and needs no privileges, so it also
// works under CGO_ENABLED=0 cross-compilation. Live interface capture is a
// separately scoped future feature.
type Replay struct {
	g      *Gateway
	path   string
	maxPPS int // 0 = no artificial pacing
	stopCh chan struct{}
	once   sync.Once
}

// NewReplay builds a replay source over a gateway. path is a classic .pcap
// file; maxPPS optionally caps the emission rate (>0).
func NewReplay(g *Gateway, path string, maxPPS int) *Replay {
	return &Replay{
		g:      g,
		path:   path,
		maxPPS: maxPPS,
		stopCh: make(chan struct{}),
	}
}

// Start validates the capture before reporting success and begins replaying it.
func (r *Replay) Start() error {
	f, err := os.Open(r.path)
	if err != nil {
		return err
	}
	reader, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()
		return err
	}
	go r.loop(f, reader)
	return nil
}

// Stop halts replay.
func (r *Replay) Stop() {
	r.once.Do(func() { close(r.stopCh) })
}

func (r *Replay) loop(f *os.File, reader *pcapgo.Reader) {
	defer f.Close()

	lt := reader.LinkType()
	pacing := time.Duration(0)
	if r.maxPPS > 0 {
		pacing = time.Second / time.Duration(r.maxPPS)
	}
	var last time.Time

	for {
		select {
		case <-r.stopCh:
			return
		default:
		}
		data, _, err := reader.ReadPacketData()
		if err != nil {
			// EOF (or corrupt tail) ends the replay.
			return
		}
		pkt := &pipeline.Packet{Data: data, Captured: time.Now(), Link: lt}
		if r.g.HandlePacket(context.Background(), pkt) != "" {
			if pacing > 0 {
				if now := time.Now(); !last.IsZero() {
					if d := now.Sub(last); d < pacing {
						time.Sleep(pacing - d)
					}
				}
				last = time.Now()
			}
		}
	}
}
