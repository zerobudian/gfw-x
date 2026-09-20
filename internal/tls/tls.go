package tls

import (
	"encoding/binary"
	"fmt"
)

// Errors from SNI extraction.
var (
	ErrNotTLS      = fmt.Errorf("tls: not a TLS record")
	ErrNoSNI       = fmt.Errorf("tls: no SNI")
	ErrTruncated   = fmt.Errorf("tls: truncated")
)

// ClientHello represents the leading TLS ClientHello metadata we care about.
type ClientHello struct {
	SNI         string
	Version     uint16
	ALPNProto   []string
	Extensions  int
	IsQUICInt   bool // whether initial packet (handshake) on UDP
}

// HasSNI returns true when an SNI server name was present.
func (ch *ClientHello) HasSNI() bool { return ch.SNI != "" }

// ParseClientHello extracts SNI + ALPN from a ClientHello record.
// data should begin at the start of a TLS record (0x16 0x03 ...).
func ParseClientHello(data []byte) (*ClientHello, error) {
	if len(data) < 5 {
		return nil, ErrTruncated
	}
	if data[0] != 0x16 {
		return nil, ErrNotTLS
	}
	ch := &ClientHello{
		Version: binary.BigEndian.Uint16(data[1:3]),
	}
	// record length
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	end := 5 + recLen
	if end > len(data) {
		end = len(data)
	}
	handshake := data[5:end]
	if len(handshake) < 4 {
		return nil, ErrTruncated
	}
	// handshake type = 0x01 (ClientHello); body = 4-byte header then body
	// After the 4-byte header: client_version(2), random(32), session_id(1+len)
	p := 4
	if p+2 > len(handshake) {
		return ch, nil
	}
	ch.Version = binary.BigEndian.Uint16(handshake[p : p+2])
	p += 2 + 32 // skip client_version + random
	if p+1 > len(handshake) {
		return ch, nil
	}
	sidLen := int(handshake[p])
	p += 1 + sidLen
	if p+2 > len(handshake) {
		return ch, nil
	}
	ciphLen := int(binary.BigEndian.Uint16(handshake[p : p+2]))
	p += 2 + ciphLen
	if p+1 > len(handshake) {
		return ch, nil
	}
	compLen := int(handshake[p])
	p += 1 + compLen
	if p+2 > len(handshake) {
		return ch, nil
	}
	extTotal := int(binary.BigEndian.Uint16(handshake[p : p+2]))
	p += 2
	if p+extTotal > len(handshake) {
		extTotal = len(handshake) - p
	}
	extEnd := p + extTotal
	for p+4 <= extEnd {
		extType := binary.BigEndian.Uint16(handshake[p : p+2])
		extLen := int(binary.BigEndian.Uint16(handshake[p+2 : p+4]))
		p += 4
		if p+extLen > extEnd {
			break
		}
		body := handshake[p : p+extLen]
		p += extLen
		ch.Extensions++
		switch extType {
		case 0: // server_name
			if len(body) < 2 {
				continue
			}
			listLen := int(binary.BigEndian.Uint16(body[0:2]))
			q := 2
			qEnd := 2 + listLen
			for q+3 <= qEnd && q+3 <= len(body) {
				nameType := body[q]
				nameLen := int(binary.BigEndian.Uint16(body[q+1 : q+3]))
				q += 3
				if nameType == 0 && q+nameLen <= len(body) {
					ch.SNI = string(body[q : q+nameLen])
					break
				}
				q += nameLen
			}
		case 16: // ALPN
			if len(body) < 2 {
				continue
			}
			q := 0
			for q+1 < len(body) {
				l := int(body[q])
				q++
				if q+l <= len(body) {
					ch.ALPNProto = append(ch.ALPNProto, string(body[q:q+l]))
					q += l
				} else {
					break
				}
			}
		}
	}
	return ch, nil
}

// ParseQUICClientHello extracts SNI from a QUIC Initial CRYPTO frame's
// ClientHello is not trivially aligned (depends on version / frame layout).
// We implement a best-effort scan for the SNI extension to avoid full QUIC
// parsing; it powers the ~high-confidence classification in the detector.
func ParseQUICInitial(data []byte) (string, error) {
	// Minimal: search a client hello magic + server_name ext pattern.
	// This is intentionally conservative and bounded.
	idx := findCHMagic(data)
	if idx < 0 {
		return "", ErrNoSNI
	}
	ch, err := ParseClientHello(data[idx:])
	if err != nil {
		// attempt a manual scan
		return "", err
	}
	if ch.HasSNI() {
		return ch.SNI, nil
	}
	return "", ErrNoSNI
}

func findCHMagic(data []byte) int {
	for i := 0; i+1 < len(data); i++ {
		if data[i] == 0x01 && i+1 < len(data) && data[i+1] == 0x00 {
			// heuristic: ClientHello handshake type 0x01 followed by length pattern
			return i
		}
	}
	return -1
}