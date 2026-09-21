package logging

import "testing"

// BenchmarkFileStorageWriteBatch measures JSONL write throughput of a single
// batch under the current sync policy (before/after fsync change).
func BenchmarkFileStorageWriteBatch(b *testing.B) {
	fs, err := NewFileStorage(b.TempDir(), "jsonl", 1<<30, 5)
	if err != nil {
		b.Fatal(err)
	}
	defer fs.Close()

	entries := make([]*Entry, 512)
	for i := range entries {
		entries[i] = &Entry{Action: "allow", Domain: "example.com"}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := fs.WriteBatch(entries); err != nil {
			b.Fatal(err)
		}
	}
}
