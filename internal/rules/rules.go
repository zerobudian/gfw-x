package rules

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Kind is the disposition of a rule.
type Kind string

const (
	KindAllow     Kind = "allow"
	KindBlock     Kind = "block"
	KindObserve   Kind = "observe"
	KindRateLimit Kind = "ratelimit"
)

// Field is the matcher target.
type Field string

const (
	FieldDomain    Field = "domain"
	FieldDomainSfx Field = "domain_suffix"
	FieldWildcard  Field = "wildcard"
	FieldIP        Field = "ip"
	FieldCIDR      Field = "cidr"
	FieldASN       Field = "asn"
	FieldProtocol  Field = "protocol"
	FieldDNS       Field = "dns"
	FieldSNI       Field = "sni"
	FieldPort      Field = "port"
)

// allFields is the set of known matcher fields.
var allFields = map[Field]bool{
	FieldDomain: true, FieldDomainSfx: true, FieldWildcard: true,
	FieldIP: true, FieldCIDR: true, FieldASN: true,
	FieldProtocol: true, FieldDNS: true, FieldSNI: true, FieldPort: true,
	Field("category"): true,
}

// Matcher is a single condition inside a rule.
type Matcher struct {
	Field Field  `yaml:"field" json:"field"`
	Value string `yaml:"value" json:"value"`
}

// Rule is a single policy rule.
type Rule struct {
	ID       string    `yaml:"id" json:"id"`
	Name     string    `yaml:"name" json:"name"`
	Kind     Kind      `yaml:"kind" json:"kind"`
	Enabled  bool      `yaml:"enabled" json:"enabled"`
	Category string    `yaml:"category" json:"category"`
	Matchers []Matcher `yaml:"matchers" json:"matchers"`
	Hits     uint64    `yaml:"hits" json:"hits"`
	LastHit  time.Time `yaml:"last_hit" json:"last_hit"`
	Source   string    `yaml:"source" json:"source,omitempty"` // imported file / preset
	Comment  string    `yaml:"comment" json:"comment,omitempty"`
}

// NewID allocates a stable, short rule id.
func NewID(prefix string) string {
	return prefix + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

// Label returns a human readable identifier for the rule.
func (r *Rule) Label() string {
	if r.Name != "" {
		return r.Name
	}
	if len(r.Matchers) > 0 {
		return string(r.Matchers[0].Field) + ":" + r.Matchers[0].Value
	}
	return r.ID
}

// Matches determines whether m matches a DOMAIN label (for domain-family fields).
// Wildcard patterns use '*' as a single label wildcard; a leading '*' is treated
// as a suffix match.
func (m Matcher) MatchesDomain(domain string) bool {
	switch m.Field {
	case FieldDomain:
		return strings.EqualFold(m.Value, domain)
	case FieldDomainSfx, FieldWildcard:
		return matchSuffix(m.Value, domain)
	default:
		return false
	}
}

func matchSuffix(pattern, domain string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if pattern == domain {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		if strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	return strings.HasSuffix(domain, "."+pattern)
}

// Validate checks a single rule's structure.
func (r *Rule) Validate() error {
	switch r.Kind {
	case KindAllow, KindBlock, KindObserve, KindRateLimit:
	default:
		return fmt.Errorf("rule %q: invalid kind %q", r.ID, r.Kind)
	}
	if len(r.Matchers) == 0 {
		return fmt.Errorf("rule %q: must have at least one matcher", r.ID)
	}
	for _, m := range r.Matchers {
		if !allFields[m.Field] {
			return fmt.Errorf("rule %q: unknown field %q", r.ID, m.Field)
		}
		if strings.TrimSpace(m.Value) == "" {
			return fmt.Errorf("rule %q: empty value for field %q", r.ID, m.Field)
		}
	}
	return nil
}

// Conflict describes overlap between two rules.
type Conflict struct {
	A     *Rule
	B     *Rule
	Field string
	Value string
}

// ConflictsWith reports whether r overlaps o in an actionable way.
// Rules of the same kind never conflict. An allow↔block pair that share a
// concrete matcher value is a real ambiguity worth reporting.
func (r *Rule) ConflictsWith(o *Rule) (bool, string) {
	if r.ID == o.ID || !r.Enabled || !o.Enabled {
		return false, ""
	}
	if r.Kind == o.Kind {
		return false, ""
	}
	isControl := func(k Kind) bool { return k == KindAllow || k == KindBlock }
	if !isControl(r.Kind) || !isControl(o.Kind) {
		return false, ""
	}
	for _, rm := range r.Matchers {
		for _, om := range o.Matchers {
			if rm.Field == om.Field && rm.Field != FieldPort && strings.EqualFold(rm.Value, om.Value) {
				return true, "matcher:" + string(rm.Field)
			}
		}
	}
	return false, ""
}

// FindConflicts returns a list of conflicts across a set of rules.
func FindConflicts(rs []*Rule) []Conflict {
	var out []Conflict
	for i := 0; i < len(rs); i++ {
		if !rs[i].Enabled {
			continue
		}
		for j := i + 1; j < len(rs); j++ {
			ok, field := rs[i].ConflictsWith(rs[j])
			if ok {
				out = append(out, Conflict{A: rs[i], B: rs[j], Field: field, Value: firstMatch(rs[i], rs[j])})
			}
		}
	}
	return out
}

func firstMatch(a, b *Rule) string {
	for _, am := range a.Matchers {
		for _, bm := range b.Matchers {
			if am.Field == bm.Field && strings.EqualFold(am.Value, bm.Value) {
				return am.Value
			}
		}
	}
	return ""
}

// ---- Parsing helpers ----

// ParseTXT parses the TXT rule format:
//
//	ALLOW github.com
//	ALLOW *.pages.dev
//	BLOCK example.com
//	BLOCK_CATEGORY gambling
//	RATELIMIT proto:quic
//	OBSERVE sni:* '*'                    (not used)
//
// The first token is the kind; BLOCK_CATEGORY maps to a category matcher.
func ParseTXT(line string, src string) (*Rule, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return nil, nil // skip
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil, nil
	}
	kindTok := strings.ToUpper(fields[0])
	var kind Kind
	var field Field
	switch kindTok {
	case "ALLOW":
		kind, field = KindAllow, FieldDomain
	case "BLOCK":
		kind, field = KindBlock, FieldDomain
	case "OBSERVE":
		kind, field = KindObserve, FieldDomain
	case "RATELIMIT", "RATE_LIMIT":
		kind, field = KindRateLimit, FieldDomain
	case "BLOCK_CATEGORY":
		kind, field = KindBlock, FieldCategory()
		return categoryRule(kind, fields[1], src)
	case "ALLOW_CATEGORY":
		kind, field = KindAllow, FieldCategory()
	default:
		return nil, fmt.Errorf("parse: unknown token %q", kindTok)
	}
	val := strings.TrimSpace(strings.Join(fields[1:], " "))
	// A "*." prefix expresses a wildcard / suffix match, not an exact domain.
	if field == FieldDomain && strings.HasPrefix(val, "*.") {
		field = FieldDomainSfx
	}
	return &Rule{
		ID:       NewID("txt"),
		Kind:     kind,
		Enabled:  true,
		Source:   src,
		Matchers: []Matcher{{Field: field, Value: val}},
	}, nil
}

// FieldCategory is the special category matcher emitted for *_CATEGORY lines.
func FieldCategory() Field { return Field("category") }

func categoryRule(kind Kind, cat string, src string) (*Rule, error) {
	return &Rule{
		ID:       NewID("cat"),
		Kind:     kind,
		Enabled:  true,
		Category: strings.ToLower(strings.TrimSpace(cat)),
		Source:   src,
		Matchers: []Matcher{{Field: FieldCategory(), Value: strings.ToLower(strings.TrimSpace(cat))}},
	}, nil
}

// ParseBytes parses rule data in any supported format (json, yaml, txt).
func ParseBytes(data []byte, source string) ([]*Rule, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, nil
	}
	// Structured formats.
	if strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{") {
		jrules, jerr := parseJSON(data, source)
		if jerr == nil {
			return validateSet(jrules)
		}
		yrules, yerr := parseYAML(data, source)
		if yerr == nil {
			return validateSet(yrules)
		}
		return nil, fmt.Errorf("structured rule parse failed (json: %v, yaml: %v)", jerr, yerr)
	}
	// YAML document marker or list block.
	if strings.HasPrefix(trimmed, "-") || strings.Contains(trimmed, "rules:") {
		yrules, yerr := parseYAML(data, source)
		if yerr == nil {
			return validateSet(yrules)
		}
		return nil, yerr
	}
	// Otherwise treat each line as TXT.
	lines := strings.Split(trimmed, "\n")
	var rules []*Rule
	for _, ln := range lines {
		r, err := ParseTXT(ln, source)
		if err != nil {
			return nil, err
		}
		if r != nil {
			rules = append(rules, r)
		}
	}
	return validateSet(rules)
}

func parseJSON(data []byte, source string) ([]*Rule, error) {
	var list []*Rule
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	for _, r := range list {
		r.Source = source
		if r.ID == "" {
			r.ID = NewID("json")
		}
	}
	return list, nil
}

func parseYAML(data []byte, source string) ([]*Rule, error) {
	var raw struct {
		Rules []*Rule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		// maybe it's a bare list
		var list []*Rule
		if err2 := yaml.Unmarshal(data, &list); err2 != nil {
			return nil, err
		}
		return list, nil
	}
	if raw.Rules == nil {
		// try direct list again
		var list []*Rule
		if err2 := yaml.Unmarshal(data, &list); err2 != nil {
			return nil, err2
		}
		return list, nil
	}
	for _, r := range raw.Rules {
		r.Source = source
		if r.ID == "" {
			r.ID = NewID("yaml")
		}
	}
	return raw.Rules, nil
}

func validateSet(rs []*Rule) ([]*Rule, error) {
	for _, r := range rs {
		if err := r.Validate(); err != nil {
			return nil, err
		}
	}
	return rs, nil
}

// ---- Serialization ----

// MarshalYAML renders rules into the canonical YAML document.
func MarshalYAML(rs []*Rule) ([]byte, error) {
	doc := struct {
		Rules []*Rule `yaml:"rules"`
	}{Rules: sorted(rs)}
	return yaml.Marshal(doc)
}

// MarshalJSON renders rules into a JSON array.
func MarshalJSON(rs []*Rule) ([]byte, error) {
	return json.MarshalIndent(sorted(rs), "", "  ")
}

// MarshalTXT renders rules into the TXT format.
func MarshalTXT(rs []*Rule) string {
	var b strings.Builder
	for _, r := range sorted(rs) {
		b.WriteString(txtLine(r))
		b.WriteByte('\n')
	}
	return b.String()
}

func txtLine(r *Rule) string {
	kindTok := map[Kind]string{KindAllow: "ALLOW", KindBlock: "BLOCK", KindObserve: "OBSERVE", KindRateLimit: "RATELIMIT"}[r.Kind]
	if len(r.Matchers) == 1 && r.Matchers[0].Field == FieldCategory() {
		return kindTok + "_CATEGORY " + strings.ToUpper(r.Matchers[0].Value)
	}
	var vals []string
	for _, m := range r.Matchers {
		v := m.Value
		if m.Field == FieldDomain || m.Field == FieldDomainSfx || m.Field == FieldWildcard || m.Field == FieldIP || m.Field == FieldCIDR || m.Field == FieldASN || m.Field == FieldDNS || m.Field == FieldSNI {
			vals = append(vals, v)
		} else {
			vals = append(vals, string(m.Field)+":"+v)
		}
	}
	return kindTok + " " + strings.Join(vals, " ")
}

func sorted(rs []*Rule) []*Rule {
	out := make([]*Rule, len(rs))
	copy(out, rs)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
