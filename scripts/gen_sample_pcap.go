//go:build ignore

package main

import (
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func mustIP(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		panic("bad ip " + s)
	}
	return ip
}

// frame builds an Ethernet/IPv4/UDP frame carrying payload.
func frame(sport, dport uint16, src, dst string, payload []byte) []byte {
	b := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP,
		SrcIP: mustIP(src), DstIP: mustIP(dst)}
	udp := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
	_ = udp.SetNetworkLayerForChecksum(ip)
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		DstMAC:       net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeIPv4,
	}
	if err := gopacket.SerializeLayers(b, opts, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		panic(err)
	}
	return b.Bytes()
}

func main() {
	payload := []byte{
		0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0,
		0x00, 0x01, 0x00, 0x01,
	}
	f, err := os.Create("sample.pcap")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		panic(err)
	}
	hosts := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "208.67.222.222"}
	for i := 0; i < 5; i++ {
		fr := frame(40000+uint16(i), 53, "192.168.0.1", hosts[i], payload)
		ci := gopacket.CaptureInfo{Timestamp: time.Unix(1700000000+int64(i), 0), CaptureLength: len(fr), Length: len(fr)}
		if err := w.WritePacket(ci, fr); err != nil {
			panic(err)
		}
	}
	_ = f.Sync()
}
