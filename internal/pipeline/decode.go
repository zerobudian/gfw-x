package pipeline

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Ingress is the normalized L3/L4 identity extracted from a Packet. It is the
// only form consumed by the flow engine (via gateway.HandlePacket). Keeping
// the decode provider-independent means policy/detector never touch pcapgo or
// netfilter wire formats.
type Ingress struct {
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Transport string // "tcp" | "udp"
	Payload   []byte // leading application bytes (capped)
}

const maxHints = 1024

// DecodePacket decodes an Ethernet/IP packet into an Ingress. It returns nil
// when the frame carries no classifiable L3/L4 data (ARP, ICMP, bare IP), and
// an error for structurally malformed frames that must not silently drop.
func DecodePacket(p *Packet) (*Ingress, error) {
	if p == nil || len(p.Data) == 0 {
		return nil, fmt.Errorf("pipeline: empty packet")
	}
	pkt := gopacket.NewPacket(p.Data, p.Link, gopacket.DecodeOptions{NoCopy: true, Lazy: true})
	netL := pkt.NetworkLayer()
	if netL == nil {
		return nil, nil // non-IP L3 (ARP etc.) — nothing to classify
	}
	tr := pkt.TransportLayer()
	srcEP, dstEP := netL.NetworkFlow().Endpoints()
	if srcEP == gopacket.InvalidEndpoint || dstEP == gopacket.InvalidEndpoint {
		return nil, nil
	}

	in := &Ingress{SrcIP: srcEP.String(), DstIP: dstEP.String()}
	switch t := tr.(type) {
	case *layers.TCP:
		in.Transport = "tcp"
		in.SrcPort, in.DstPort = uint16(t.SrcPort), uint16(t.DstPort)
		in.Payload = t.LayerPayload()
	case *layers.UDP:
		in.Transport = "udp"
		in.SrcPort, in.DstPort = uint16(t.SrcPort), uint16(t.DstPort)
		in.Payload = t.LayerPayload()
	default:
		// ICMP / other L4: no ports, treated as unknown by the flow engine.
		return nil, nil
	}
	if len(in.Payload) > maxHints {
		in.Payload = in.Payload[:maxHints]
	}
	return in, nil
}
