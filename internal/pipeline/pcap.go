package pipeline

import (
	"context"
	"io"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// PcapSource is an offline PacketSource that replays a classic .pcap capture.
// It is pure-Go (gopacket/pcapgo, offline, no cgo) so it builds and runs under
// CGO_ENABLED=0 cross-compilation and needs no privileges.
type PcapSource struct {
	path string
	pcap *pcapgo.Reader
	file *os.File

	mtx    sync.Mutex
	closed bool
	stopCh chan struct{}

	linkType layers.LinkType
}

// NewPcapSource opens path lazily on Start.
func NewPcapSource(path string) *PcapSource {
	return &PcapSource{path: path, stopCh: make(chan struct{})}
}

// Start opens and validates the capture.
func (s *PcapSource) Start() error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.closed {
		return ErrSourceClosed
	}
	if s.file != nil {
		return nil
	}
	f, err := os.Open(s.path)
	if err != nil {
		return err
	}
	r, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()
		return err
	}
	s.file, s.pcap = f, r
	s.linkType = r.LinkType()
	return nil
}

// LinkType returns the capture link type (valid after Start).
func (s *PcapSource) LinkType() layers.LinkType { return s.linkType }

// Next reads the next raw frame, wraps it as a Packet and returns it.
func (s *PcapSource) Next(ctx context.Context) (*Packet, error) {
	p := &Packet{}
	select {
	case <-ctx.Done():
		return nil, ErrStopped
	case <-s.stopCh:
		return nil, ErrStopped
	default:
	}
	raw, _, err := s.pcap.ReadPacketData()
	if err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, err
	}
	p.Data = raw
	p.Captured = time.Now()
	return p, nil
}

// Stop closes the underlying file and marks the source closed.
func (s *PcapSource) Stop() error {
	s.mtx.Lock()
	defer s.mtx.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.stopCh)
	if s.file != nil {
		err := s.file.Close()
		s.file, s.pcap = nil, nil
		return err
	}
	return nil
}
