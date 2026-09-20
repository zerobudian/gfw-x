package dns

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Errors from DNS parsing.
var (
	ErrShort    = fmt.Errorf("dns: packet too short")
	ErrNotQuery = fmt.Errorf("dns: not a query")
)

// Name parses a DNS name at off, following compression pointers.
// It returns the joined name and the offset just past the parsed pointer chain.
func Name(data []byte, off int) (string, int, error) {
	var labels []string
	pos := off
	steps := 0
	for steps < 32 {
		steps++
		if pos >= len(data) {
			return "", off, ErrShort
		}
		b := data[pos]
		switch {
		case b == 0:
			pos++
			return join(labels), pos, nil
		case b&0xC0 == 0xC0: // compression pointer
			if pos+1 >= len(data) {
				return "", off, ErrShort
			}
			ptr := int(binary.BigEndian.Uint16(data[pos:pos+2])) & 0x3FFF
			resolved, _, err := resolve(data, ptr, 0)
			if err != nil {
				return "", off, err
			}
			labels = append(labels, resolved)
			return join(labels), pos + 2, nil
		default:
			n := int(b)
			if n == 0 || n > 63 || pos+1+n > len(data) {
				return "", off, ErrShort
			}
			labels = append(labels, string(data[pos+1:pos+1+n]))
			pos += 1 + n
		}
	}
	return "", off, fmt.Errorf("dns: name loop")
}

func resolve(data []byte, off, depth int) (string, int, error) {
	if depth > 16 {
		return "", off, fmt.Errorf("dns: compression loop")
	}
	if off >= len(data) {
		return "", off, ErrShort
	}
	var labels []string
	pos := off
	for depth < 32 {
		depth++
		if pos >= len(data) {
			return "", off, ErrShort
		}
		b := data[pos]
		switch {
		case b == 0:
			return join(labels), pos + 1, nil
		case b&0xC0 == 0xC0:
			if pos+1 >= len(data) {
				return "", off, ErrShort
			}
			ptr := int(binary.BigEndian.Uint16(data[pos:pos+2])) & 0x3FFF
			resolved, _, err := resolve(data, ptr, depth+1)
			if err != nil {
				return "", off, err
			}
			if len(labels) > 0 {
				resolved = join(labels) + "." + resolved
			}
			return resolved, pos + 2, nil
		default:
			n := int(b)
			if n == 0 || n > 63 || pos+1+n > len(data) {
				return "", off, ErrShort
			}
			labels = append(labels, string(data[pos+1:pos+1+n]))
			pos += 1 + n
		}
	}
	return "", off, fmt.Errorf("dns: name loop")
}

func join(labels []string) string { return strings.Join(labels, ".") }

// Question holds a parsed DNS question.
type Question struct {
	Name   string
	QType  uint16
	QClass uint16
}

// Query parses a DNS query and returns its first question.
func Query(pkt []byte) (Question, error) {
	if len(pkt) < 12 {
		return Question{}, ErrShort
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if flags&0x8000 != 0 {
		return Question{}, ErrNotQuery // response
	}
	qdcount := binary.BigEndian.Uint16(pkt[4:6])
	if qdcount == 0 {
		return Question{}, fmt.Errorf("dns: no questions")
	}
	name, off, err := Name(pkt, 12)
	if err != nil {
		return Question{}, err
	}
	if off+4 > len(pkt) {
		return Question{}, ErrShort
	}
	return Question{
		Name:   strings.ToLower(name),
		QType:  binary.BigEndian.Uint16(pkt[off : off+2]),
		QClass: binary.BigEndian.Uint16(pkt[off+2 : off+4]),
	}, nil
}

// TypeLabel maps a QTYPE to a friendly label.
func TypeLabel(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 28:
		return "AAAA"
	case 5:
		return "CNAME"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 6:
		return "SOA"
	case 33:
		return "SRV"
	case 65:
		return "HTTPS"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}