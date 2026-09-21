package detect

import "testing"

func TestWireGuardFingerprint(t *testing.T) {
	e := NewEngine(true, 0.85, false)
	// WireGuard init packet signature.
	data := make([]byte, 32)
	data[0] = 0x01 // reserved high bits of type 4 (handshake initiation)
	d := e.Lookup(Sample{Proto: "udp", DstPort: 51820, Data: data}, &Features{})
	if d.Protocol != "wireguard" {
		t.Fatalf("protocol=%q want wireguard", d.Protocol)
	}
	if d.Confidence < 0.9 {
		t.Fatalf("confidence=%v want >=0.9", d.Confidence)
	}
}

func TestHTTPConnectFingerprint(t *testing.T) {
	e := NewEngine(true, 0.85, false)
	data := []byte("CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	d := e.Lookup(Sample{Proto: "tcp", Data: data}, nil)
	if d.Protocol != "http_connect" {
		t.Fatalf("protocol=%q want http_connect", d.Protocol)
	}
}

func TestDisabledReturnsAllow(t *testing.T) {
	e := NewEngine(false, 0.85, false)
	d := e.Lookup(Sample{Proto: "udp", Data: make([]byte, 32)}, nil)
	if d.Protocol != "none" || d.Action != ActionAllow {
		t.Fatalf("disabled engine should be pass-through, got %+v", d)
	}
}

func TestBehavioralBoost(t *testing.T) {
	e := NewEngine(true, 0.5, false)
	f := &Features{UpDownRatio: 2.0, Alternation: 0.9, MinPkt: 200, Lifetime: 600, Handshake: 0.1}
	d := e.Lookup(Sample{Proto: "tcp", Data: []byte{0x01, 0x02, 0x03}}, f)
	if d.Confidence <= 0.05 {
		t.Fatalf("behavioral features should boost confidence, got %v", d.Confidence)
	}
	if d.Action == ActionAllow {
		t.Fatalf("suspicious behavior should be at least observe, got %+v", d)
	}
}

// ----- benchmarks -----

func BenchmarkLookup(b *testing.B) {
	e := NewEngine(true, 0.85, false)
	s := Sample{Proto: "udp", Data: make([]byte, 32)}
	s.Data[0] = 0x01
	f := &Features{UpDownRatio: 1.2, Alternation: 0.8, MinPkt: 150, Lifetime: 500, Handshake: 0.2}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e.Lookup(s, f)
	}
}
