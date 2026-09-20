package gateway

import (
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
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

// Start begins replaying the capture in the background.
func (r *Replay) Start() {
	go r.loop()
}

// Stop halts replay.
func (r *Replay) Stop() {
	r.once.Do(func() { close(r.stopCh) })
}

func (r *Replay) loop() {
	f, err := os.Open(r.path)
	if err != nil {
		return
	}
	defer f.Close()

	reader, err := pcapgo.NewReader(f)
	if err != nil {
		return
	}

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
		if t := r.g.ingestFromReplay(data, lt); t {
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

// ingestFromReplay decodes one captured frame and feeds the gateway. Returns
// false when the frame carries no classifiable L3/L4 data or is malformed.
func (g *Gateway) ingestFromReplay(data []byte, lt layers.LinkType) bool {
	pkt := gopacket.NewPacket(data, lt, gopacket.DecodeOptions{NoCopy: true, Lazy: true})
	netL := pkt.NetworkLayer()
	if netL == nil {
		return false
	}
	transL := pkt.TransportLayer()
	srcEP, dstEP := netL.NetworkFlow().Endpoints()
	if srcEP == gopacket.InvalidEndpoint || dstEP == gopacket.InvalidEndpoint {
		return false
	}

	transport, srcPort, dstPort := "", 0, 0
	var payload []byte
	switch tr := transL.(type) {
	case *layers.TCP:
		transport, srcPort, dstPort = "tcp", int(tr.SrcPort), int(tr.DstPort)
		payload = tr.LayerPayload()
	case *layers.UDP:
		transport, srcPort, dstPort = "udp", int(tr.SrcPort), int(tr.DstPort)
		payload = tr.LayerPayload()
	default:
		// ICMP / ARP / bare IP: pass through with no ports; gateway treats
		// them as unknown (slow path) only if they look relevant.
		return false
	}
	if len(payload) > 1024 {
		payload = payload[:1024]
	}

	g.Ingest(&Traffic{
		SrcIP:       srcEP.String(),
		DstIP:       dstEP.String(),
		SrcPort:     uint16(srcPort),
		DstPort:     uint16(dstPort),
		Transport:   transport,
		Sample:      payload,
		UpBytes:     uint64(len(payload)),
		DownBytes:   0,
		UpPkts:      1,
		DownPkts:    0,
		LifetimeSec: 0.5,
	})
	return true
}