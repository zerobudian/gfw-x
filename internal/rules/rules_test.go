package rules

import (
	"net"
	"testing"
)

func mustRule(t *testing.T, kind Kind, field Field, value string) *Rule {
	t.Helper()
	r := &Rule{ID: NewID("t"), Kind: kind, Enabled: true, Matchers: []Matcher{{Field: field, Value: value}}}
	if err := r.Validate(); err != nil {
		t.Fatalf("rule %v invalid: %v", r, err)
	}
	return r
}

func TestSuffixMatch(t *testing.T) {
	cases := []struct {
		pattern, domain string
		want            bool
	}{
		{"*.pages.dev", "my.pages.dev", true},
		{"*.pages.dev", "pages.dev", false},
		{"github.com", "github.com", true},
		{"github.com", "api.github.com", true},
		{"github.com", "notgithub.com", false},
		{"githubusercontent.com", "raw.githubusercontent.com", true},
		{"qq.com", "xx.qq.com", true},
	}
	for _, c := range cases {
		m := Matcher{Field: FieldDomainSfx, Value: c.pattern}
		if got := m.MatchesDomain(c.domain); got != c.want {
			t.Errorf("MatchesDomain(%q,%q)=%v want %v", c.pattern, c.domain, got, c.want)
		}
	}
}

func TestConflictDetection(t *testing.T) {
	allow := mustRule(t, KindAllow, FieldDomain, "example.com")
	block := mustRule(t, KindBlock, FieldDomain, "example.com")
	ok, field := allow.ConflictsWith(block)
	if !ok {
		t.Fatal("expected allow/block conflict for same domain")
	}
	if field != "matcher:domain" {
		t.Fatalf("field=%q want matcher:domain", field)
	}
	// same kind → no conflict
	if ok, _ := allow.ConflictsWith(mustRule(t, KindAllow, FieldDomain, "example.com")); ok {
		t.Fatal("same-kind rules must not conflict")
	}
	// different domains → no conflict
	if ok, _ := allow.ConflictsWith(mustRule(t, KindBlock, FieldDomain, "other.com")); ok {
		t.Fatal("different domain must not conflict")
	}
}

func TestParseTXT(t *testing.T) {
	parse := func(line string) (*Rule, error) { return ParseTXT(line, "test") }
	for _, line := range []string{"", "# comment", "; note"} {
		if r, err := parse(line); r != nil || err != nil {
			t.Errorf("skippable line %q => r=%v err=%v", line, r, err)
		}
	}
	r, err := parse("ALLOW github.com")
	if err != nil || r.Kind != KindAllow || r.Matchers[0].Field != FieldDomain {
		t.Fatalf("ALLOW parse failed: %v %v", r, err)
	}
	r, err = parse("BLOCK_CATEGORY gambling")
	if err != nil || r.Kind != KindBlock || r.Category != "gambling" {
		t.Fatalf("BLOCK_CATEGORY parse failed: %v %v", r, err)
	}
	if _, err := parse("BOGUS foo.com"); err == nil {
		t.Fatal("expected error for unknown token")
	}
}

func TestParseBytesFormats(t *testing.T) {
	txt := "ALLOW github.com\nBLOCK example.com\nBLOCK_CATEGORY malicious\n"
	rs, err := ParseBytes([]byte(txt), "txt")
	if err != nil || len(rs) != 3 {
		t.Fatalf("txt parse: n=%d err=%v", len(rs), err)
	}
	jsonData, _ := MarshalJSON(rs)
	rs2, err := ParseBytes(jsonData, "json")
	if err != nil || len(rs2) != 3 {
		t.Fatalf("json roundtrip: n=%d err=%v", len(rs2), err)
	}
	yamlData, _ := MarshalYAML(rs)
	rs3, err := ParseBytes(yamlData, "yaml")
	if err != nil || len(rs3) != 3 {
		t.Fatalf("yaml roundtrip: n=%d err=%v", len(rs3), err)
	}
}

func TestRepoEvalPriority(t *testing.T) {
	repo := NewRepo()
	allowGithub := allowDomain("github.com")
	blockSuffix := &Rule{ID: NewID("t"), Kind: KindBlock, Enabled: true,
		Matchers: []Matcher{{Field: FieldDomainSfx, Value: "*.pages.dev"}}}
	repo.Replace([]*Rule{blockSuffix, allowGithub})

	// explicit allow github.com
	d, _ := repo.Eval(&Attributes{Domain: "github.com"})
	if d == nil || d.Action != "allow" || d.MatchedRule != allowGithub.Label() {
		t.Fatalf("github should be explicitly allowed, got %+v", d)
	}
	// suffix block for pages.dev
	d, _ = repo.Eval(&Attributes{Domain: "foo.pages.dev"})
	if d == nil || d.Action != "block" {
		t.Fatalf("pages.dev should be blocked, got %+v", d)
	}
	// unmatched → nil (default handled by policy)
	d, _ = repo.Eval(&Attributes{Domain: "unknown.org"})
	if d != nil {
		t.Fatalf("unmatched domain should yield nil, got %+v", d)
	}
}

func TestFindConflicts(t *testing.T) {
	rs := []*Rule{
		mustRule(t, KindAllow, FieldDomain, "x.com"),
		mustRule(t, KindBlock, FieldDomain, "x.com"),
	}
	if n := len(FindConflicts(rs)); n != 1 {
		t.Fatalf("conflicts=%d want 1", n)
	}
}

func TestRepoEvalIPCIDR(t *testing.T) {
	allowV6 := &Rule{ID: NewID("t"), Kind: KindAllow, Enabled: true,
		Matchers: []Matcher{{Field: FieldIP, Value: "2001:db8::1"}}}
	blockCIDR6 := &Rule{ID: NewID("t"), Kind: KindBlock, Enabled: true,
		Matchers: []Matcher{{Field: FieldCIDR, Value: "2001:db8::/32"}}}
	blockCIDR4 := &Rule{ID: NewID("t"), Kind: KindBlock, Enabled: true,
		Matchers: []Matcher{{Field: FieldCIDR, Value: "10.0.0.0/8"}}}
	repo := NewRepo()
	repo.Replace([]*Rule{allowV6, blockCIDR6, blockCIDR4})

	// IPv6 exact-IP rule must be matched (regression: previously compiled but
	// never evaluated, because Eval's v6 branch only consulted the CIDR tree).
	d, _ := repo.Eval(&Attributes{DstIP: net.ParseIP("2001:db8::1")})
	if d == nil || d.Action != "allow" || d.MatchedRule != allowV6.Label() {
		t.Fatalf("2001:db8::1 should be explicitly allowed, got %+v", d)
	}
	// Non-exact IPv6 inside /32 → CIDR block.
	d, _ = repo.Eval(&Attributes{DstIP: net.ParseIP("2001:db8::abcd")})
	if d == nil || d.Action != "block" {
		t.Fatalf("2001:db8::abcd should be blocked by /32, got %+v", d)
	}
	// IPv4 CIDR block.
	d, _ = repo.Eval(&Attributes{DstIP: net.ParseIP("10.1.2.3")})
	if d == nil || d.Action != "block" {
		t.Fatalf("10.1.2.3 should be blocked by 10.0.0.0/8, got %+v", d)
	}
	// Explicit IPv4 allow must override the /8 CIDR block (priority preserved).
	allowV4 := &Rule{ID: NewID("t"), Kind: KindAllow, Enabled: true,
		Matchers: []Matcher{{Field: FieldIP, Value: "10.9.9.9"}}}
	repo.Replace([]*Rule{allowV6, blockCIDR6, blockCIDR4, allowV4})
	d, _ = repo.Eval(&Attributes{DstIP: net.ParseIP("10.9.9.9")})
	if d == nil || d.Action != "allow" {
		t.Fatalf("explicit IPv4 allow must override /8 block, got %+v", d)
	}
}
