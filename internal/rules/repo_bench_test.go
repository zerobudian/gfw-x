package rules

import "testing"

func benchRepo() *RuleRepo {
	p, _ := PresetBy("developer")
	repo := NewRepo()
	repo.Replace(p.Rules)
	return repo
}

func BenchmarkEvalDomainExact(b *testing.B) {
	repo := benchRepo()
	attrs := &Attributes{Domain: "api.github.com", SNI: "api.github.com", Proto: "tls", DstPort: 443}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		repo.Eval(attrs)
	}
}

func BenchmarkEvalSuffixMiss(b *testing.B) {
	repo := benchRepo()
	attrs := &Attributes{Domain: "definitely-not-matching.example", Proto: "tcp", DstPort: 80}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		repo.Eval(attrs)
	}
}

func BenchmarkParseTXT(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = ParseTXT("ALLOW github.com", "bench")
	}
}
