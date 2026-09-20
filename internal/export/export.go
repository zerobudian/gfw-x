package export

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"gfw-x/internal/config"
	"gfw-x/internal/metrics"
	"gfw-x/internal/rules"
	"gfw-x/internal/version"
)

// Options controls export behavior.
type Options struct {
	Redact bool   // privacy: mask IPs
	Rows   int    // max rows exported
	ZIP    bool   // pack into a .zip archive
	OutDir string // output directory (used when !ZIP)
}

// Bundle is collected data ready for export.
type Bundle struct {
	Config   *config.Config
	Rules    []*rules.Rule
	Metrics  *metrics.Registry
	Format   string // jsonl | csv | ring
}

// writeFile writes data to path with 0644 perms.
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}

// Run performs "parse-free" export of current runtime state.
func Run(b *Bundle, opts Options) (string, error) {
	if opts.Redact {
		b.Redact()
	}
	var out string
	if opts.ZIP {
		out = filepath.Join(opts.OutDir, "gfwx-export.zip")
		if err := writeZIP(out, b, opts); err != nil {
			return "", err
		}
		return out, nil
	}
	dir := opts.OutDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	out = dir
	if err := writeEvents(b, filepath.Join(dir, "events.jsonl")); err != nil {
		return "", err
	}
	if err := writeTrafficCSV(b, filepath.Join(dir, "traffic.csv")); err != nil {
		return "", err
	}
	if data, err := rules.MarshalYAML(b.Rules); err == nil {
		if err := writeFile(filepath.Join(dir, "rules.yaml"), data); err != nil {
			return "", err
		}
	}
	if data, err := json.MarshalIndent(systemInfo(), "", "  "); err == nil {
		_ = writeFile(filepath.Join(dir, "system.json"), data)
	}
	if data, err := json.MarshalIndent(summary(b), "", "  "); err == nil {
		_ = writeFile(filepath.Join(dir, "summary.json"), data)
	}
	return out, nil
}

// Redact privacy-masks events when opts.Redact is set.
func (b *Bundle) Redact() {
	if b.Metrics == nil {
		return
	}
	for _, e := range b.Metrics.Events() {
		e.Src = maskIP(e.Src)
		e.Dst = maskIP(e.Dst)
	}
}

func maskIP(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return s[:i+1] + "0"
		}
	}
	return s
}

func writeZIP(path string, b *Bundle, opts Options) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	defer zw.Close()

	add := func(name string, data []byte) error {
		w, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	// events.jsonl
	var evData []byte
	if evData, err = eventsBytes(b); err != nil {
		return err
	}
	if err := add("events.jsonl", evData); err != nil {
		return err
	}
	// traffic.csv
	if err := add("traffic.csv", trafficCSVBytes(b)); err != nil {
		return err
	}
	// rules.yaml
	if data, err := rules.MarshalYAML(b.Rules); err == nil {
		if err := add("rules.yaml", data); err != nil {
			return err
		}
	}
	// system.json
	if data, err := json.MarshalIndent(systemInfo(), "", "  "); err == nil {
		if err := add("system.json", data); err != nil {
			return err
		}
	}
	// summary.json
	if data, err := json.MarshalIndent(summary(b), "", "  "); err == nil {
		if err := add("summary.json", data); err != nil {
			return err
		}
	}
	return nil
}

// System holds system.json content.
type System struct {
	Time       string  `json:"time"`
	Version    string  `json:"version"`
	GoVersion  string  `json:"go"`
	GOOS       string  `json:"goos"`
	GOARCH     string  `json:"goarch"`
	GOMAXPROCS int     `json:"gomaxprocs"`
	MemoryMB   float64 `json:"memory_mb"`
	NumGoroutine int   `json:"goroutines"`
}

func systemInfo() System {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return System{
		Time:       time.Now().UTC().Format(time.RFC3339),
		Version:    version.Info(),
		GoVersion:  runtime.Version(),
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		GOMAXPROCS: runtime.GOMAXPROCS(0),
		MemoryMB:   float64(m.HeapAlloc) / (1024 * 1024),
		NumGoroutine: runtime.NumGoroutine(),
	}
}

// Summary holds summary.json content.
type Summary struct {
	Mode        string `json:"mode"`
	FlowsSeen   int64  `json:"flows_seen"`
	Allowed     int64  `json:"allowed"`
	Blocked     int64  `json:"blocked"`
	Unknown     int64  `json:"unknown"`
	RateLimited int64  `json:"rate_limited"`
	BytesUp     int64  `json:"bytes_up"`
	BytesDown   int64  `json:"bytes_down"`
	ActiveFlows int64  `json:"active_flows"`
	Rules       int    `json:"rules"`
	Events      int    `json:"events"`
}

func summary(b *Bundle) Summary {
	if b.Metrics == nil {
		return Summary{}
	}
	s := b.Metrics.Snapshot()
	return Summary{
		FlowsSeen: s.FlowsSeen, Allowed: s.Allowed, Blocked: s.Blocked,
		Unknown: s.Unknown, RateLimited: s.RateLimited,
		BytesUp: s.BytesUp, BytesDown: s.BytesDown,
		ActiveFlows: b.Metrics.C.FlowsSeen.Load(), Rules: len(b.Rules),
		Events: len(b.Metrics.Events()),
	}
}

func eventsBytes(b *Bundle) ([]byte, error) {
	var out []byte
	if b.Metrics == nil {
		return out, nil
	}
	evs := b.Metrics.Events()
	for _, e := range evs {
		line, err := json.Marshal(e)
		if err != nil {
			continue
		}
		out = append(out, line...)
		out = append(out, '\n')
	}
	return out, nil
}

func writeEvents(b *Bundle, path string) error {
	data, err := eventsBytes(b)
	if err != nil {
		return err
	}
	return writeFile(path, data)
}

func trafficCSVBytes(b *Bundle) []byte {
	if b.Metrics == nil {
		return []byte{}
	}
	// CSV header + rows aggregated by destination.
	var out []byte
	out = append(out, []byte("dst,bytes_up,bytes_down\n")...)
	agg := map[string][2]int64{}
	for _, e := range b.Metrics.Events() {
		r := agg[e.Dst]
		r[0] += int64(e.BytesUp)
		r[1] += int64(e.BytesDown)
		agg[e.Dst] = r
	}
	for dst, r := range agg {
		out = append(out, []byte(dst+","+nums(r[0])+","+nums(r[1])+"\n")...)
	}
	return out
}

func writeTrafficCSV(b *Bundle, path string) error {
	return writeFile(path, trafficCSVBytes(b))
}

func nums(i int64) string {
	if i < 0 {
		i = 0
	}
	var b [20]byte
	pos := len(b)
	for {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
		if i == 0 {
			break
		}
	}
	return string(b[pos:])
}