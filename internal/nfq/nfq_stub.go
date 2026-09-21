//go:build !linux

package nfq

import (
	"context"
	"errors"

	"gfw-x/internal/config"
	"gfw-x/internal/pipeline"
)

// ErrUnsupportedPlatform is returned when NFQUEUE is requested on a platform
// without NETLINK_NETFILTER (non-Linux). PCAP mode and the synthetic generator
// remain fully supported everywhere and are unaffected.
var ErrUnsupportedPlatform = errors.New("nfq: NFQUEUE data plane requires Linux")

// Source is an unavailable stub on non-Linux platforms. It always fails to
// Start so the caller can detect the unsupported mode at startup rather than
// silently degrading to a no-op.
type Source struct{ err error }

// NewSource reports that the NFQUEUE backend is not available on this platform.
func NewSource(cfg config.NFQueueCfg) (*Source, error) {
	return &Source{err: ErrUnsupportedPlatform}, nil
}

// Start always fails on non-Linux.
func (s *Source) Start() error { return s.err }

func (s *Source) Next(ctx context.Context) (*pipeline.Packet, error) {
	return nil, ErrUnsupportedPlatform
}
func (s *Source) Stop() error { return nil }

// Sink is an unavailable verdict sink on non-Linux platforms.
type Sink struct{ err error }

// NewSink always fails on non-Linux.
func NewSink(src *Source, failMode string, overflowFn func(int64)) (*Sink, error) {
	return nil, ErrUnsupportedPlatform
}
func (s *Sink) Write(ctx context.Context, p *pipeline.Packet, v pipeline.Verdict) error {
	return ErrUnsupportedPlatform
}
func (s *Sink) Stop() error { return nil }
