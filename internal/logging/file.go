package logging

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// FileStorage writes JSONL/CSV with size-based rotation and a max file count.
type FileStorage struct {
	mu       sync.Mutex
	path     string // active file path
	dir      string
	format   string
	maxBytes int64
	maxFiles int
	f        *os.File
	curBytes int64
	w        *csv.Writer
	written  bool // header written
}

// NewFileStorage opens a rotating file storage.
func NewFileStorage(dir, format string, maxBytes int64, maxFiles int) (*FileStorage, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	fs := &FileStorage{
		dir:      dir,
		format:   format,
		maxBytes: maxBytes,
		maxFiles: maxFiles,
	}
	f, path, err := fs.newFile(time.Now())
	if err != nil {
		return nil, err
	}
	fs.f = f
	fs.path = path
	if format == "csv" {
		fs.w = csv.NewWriter(f)
		fs.writeCSVHeader()
	}
	return fs, nil
}

func (fs *FileStorage) newFile(t time.Time) (*os.File, string, error) {
	name := "events-" + t.Format("20060102-150405") + "." + fs.format
	path := filepath.Join(fs.dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	return f, path, err
}

func (fs *FileStorage) writeCSVHeader() {
	_ = fs.w.Write([]string{"timestamp", "src", "dst", "proto", "domain", "sni",
		"action", "matched_rule", "confidence", "bytes_up", "bytes_down", "duration_sec"})
	fs.w.Flush()
	if fs.f != nil {
		fs.curBytes, _ = fs.f.Seek(0, io.SeekEnd)
	}
}

// WriteBatch implements Storage.
func (fs *FileStorage) WriteBatch(entries []*Entry) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	for _, e := range entries {
		line, err := fs.encode(e)
		if err != nil {
			continue
		}
		if fs.curBytes+int64(len(line)) > fs.maxBytes {
			if err := fs.rotate(); err != nil {
				return err
			}
		}
		n, _ := fs.f.Write(line)
		fs.curBytes += int64(n)
	}
	if fs.w != nil {
		fs.w.Flush()
	}
	// Do NOT fsync on every batch: a synchronous disk flush here stalls the
	// single drain goroutine (~ms) and is unnecessary for the in-memory ring
	// that powers the dashboard. Durability is guaranteed at rotation and on
	// Close, bounding crash-loss to at most a few recent batches.
	return nil
}

func (fs *FileStorage) encode(e *Entry) ([]byte, error) {
	if fs.format == "csv" {
		rec := []string{
			e.Time.UTC().Format(time.RFC3339Nano), e.Src, e.Dst, e.Proto, e.Domain, e.SNI,
			e.Action, e.MatchedRule, strconv.FormatFloat(e.Confidence, 'f', 3, 64),
			strconv.FormatUint(e.BytesUp, 10), strconv.FormatUint(e.BytesDown, 10),
			strconv.FormatFloat(e.Duration, 'f', 3, 64),
		}
		var b strings.Builder
		w := csv.NewWriter(&b)
		_ = w.Write(rec)
		w.Flush()
		return []byte(b.String()), nil
	}
	return json.Marshal(e)
}

func (fs *FileStorage) rotate() error {
	if fs.f != nil {
		_ = fs.f.Sync()
		_ = fs.f.Close()
	}
	f, path, err := fs.newFile(time.Now())
	if err != nil {
		return err
	}
	fs.f = f
	fs.path = path
	fs.curBytes = 0
	if fs.format == "csv" {
		fs.w = csv.NewWriter(f)
		fs.writeCSVHeader()
	}
	fs.prune()
	return nil
}

func (fs *FileStorage) prune() {
	if fs.maxFiles <= 0 {
		return
	}
	matches, _ := filepath.Glob(filepath.Join(fs.dir, "events-*."+fs.format))
	sort.Strings(matches)
	for len(matches) > fs.maxFiles {
		_ = os.Remove(matches[0])
		matches = matches[1:]
	}
}

// Close flushes and closes the writer.
func (fs *FileStorage) Close() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.w != nil {
		fs.w.Flush()
	}
	if fs.f != nil {
		_ = fs.f.Sync() // persist the final batches before closing
		return fs.f.Close()
	}
	return nil
}

// RingStorage stores events only in the in-memory metrics registry.
type RingStorage struct{}

func (RingStorage) WriteBatch(entries []*Entry) error {
	// Events are surfaced live on the Dashboard; nothing to persist.
	return nil
}
func (RingStorage) Close() error { return nil }

var _ Storage = (*FileStorage)(nil)
var _ Storage = RingStorage{}

// CSVExport emits records to an io.Writer (used by gfwx export).
func CSVExport(src io.Writer, entries []*Entry) error {
	w := csv.NewWriter(src)
	if err := w.Write([]string{"timestamp", "src", "dst", "proto", "domain", "sni",
		"action", "matched_rule", "bytes_up", "bytes_down", "duration_sec"}); err != nil {
		return err
	}
	for _, e := range entries {
		if err := w.Write([]string{
			e.Time.UTC().Format(time.RFC3339Nano), e.Src, e.Dst, e.Proto, e.Domain, e.SNI,
			e.Action, e.MatchedRule, strconv.FormatUint(e.BytesUp, 10),
			strconv.FormatUint(e.BytesDown, 10), strconv.FormatFloat(e.Duration, 'f', 3, 64),
		}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

// JSONLExport emits JSON lines to an io.Writer.
func JSONLExport(src io.Writer, entries []*Entry) error {
	enc := json.NewEncoder(src)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}