package rules

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Attributes describes the traffic identity used for rule matching.
type Attributes struct {
	Domain   string
	SNI      string
	Proto    string // protocol label (tcp/udp/dns/tls/quic/http...)
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Category string // category tag assigned by parser, if any
}

// Decision is the deterministic output of rule evaluation.
type Decision struct {
	Action      string // allow|block|observe|ratelimit
	MatchedRule string
	Category    string
	Priority    int
}

// suffixTrie is a reversed trie keyed by runes for suffix/wildcard matching.
type suffixTrie struct {
	children map[byte]*suffixTrie
	rules    []*Rule // rules whose suffix terminates exactly here
}

func newSuffixTrie() *suffixTrie { return &suffixTrie{children: map[byte]*suffixTrie{}} }

// insert adds a rule for a domain suffix (reversed).
func (t *suffixTrie) insert(suffix string, r *Rule) {
	node := t
	for i := len(suffix) - 1; i >= 0; i-- {
		c := suffix[i]
		child, ok := node.children[c]
		if !ok {
			child = newSuffixTrie()
			node.children[c] = child
		}
		node = child
	}
	node.rules = append(node.rules, r)
}

// lookup returns rules whose suffix matches the FQDN (reversed traversal).
func (t *suffixTrie) lookup(domain string) []*Rule {
	var acc []*Rule
	node := t
	// walk domain from end. Stop at a node that has terminal rules.
	for i := len(domain) - 1; i >= 0; i-- {
		c := domain[i]
		child, ok := node.children[c]
		if !ok {
			return acc
		}
		node = child
		if len(node.rules) > 0 {
			// greedy: keep the longest (most specific) suffix set.
			acc = node.rules
		}
	}
	return acc
}

// cidrTree is a binary radix tree over IP prefixes.
type cidrTree struct {
	root  v4Node
	root6 v6Node
}

type v4Node struct {
	left  *v4Node
	right *v4Node
	rules []*Rule
}

type v6Node struct {
	left  *v6Node
	right *v6Node
	rules []*Rule
}

func (c *cidrTree) insert4(parts [4]byte, bits int, r *Rule) *v4Node {
	node := &c.root
	cur := node
	for i := 0; i < bits; i++ {
		b := parts[i/8]
		bit := (b >> uint(7-(i%8))) & 1
		if bit == 1 {
			if cur.right == nil {
				cur.right = &v4Node{}
			}
			cur = cur.right
		} else {
			if cur.left == nil {
				cur.left = &v4Node{}
			}
			cur = cur.left
		}
	}
	cur.rules = append(cur.rules, r)
	return cur
}

func (c *cidrTree) lookup4(ip [4]byte) []*Rule {
	var acc []*Rule
	cur := &c.root
	for i := 0; i < 32; i++ {
		if len(cur.rules) > 0 {
			acc = append(acc, cur.rules...)
		}
		b := ip[i/8]
		bit := (b >> uint(7-(i%8))) & 1
		if bit == 1 {
			if cur.right == nil {
				return acc
			}
			cur = cur.right
		} else {
			if cur.left == nil {
				return acc
			}
			cur = cur.left
		}
	}
	if len(cur.rules) > 0 {
		acc = append(acc, cur.rules...)
	}
	return acc
}

func (c *cidrTree) insert6(parts [16]byte, bits int, r *Rule) {
	cur := &c.root6
	for i := 0; i < bits; i++ {
		b := parts[i/8]
		bit := (b >> uint(7-(i%8))) & 1
		if bit == 1 {
			if cur.right == nil {
				cur.right = &v6Node{}
			}
			cur = cur.right
		} else {
			if cur.left == nil {
				cur.left = &v6Node{}
			}
			cur = cur.left
		}
	}
	cur.rules = append(cur.rules, r)
}

func (c *cidrTree) lookup6(ip [16]byte) []*Rule {
	var acc []*Rule
	cur := &c.root6
	for i := 0; i < 128; i++ {
		if len(cur.rules) > 0 {
			acc = append(acc, cur.rules...)
		}
		b := ip[i/8]
		bit := (b >> uint(7-(i%8))) & 1
		if bit == 1 {
			if cur.right == nil {
				return acc
			}
			cur = cur.right
		} else {
			if cur.left == nil {
				return acc
			}
			cur = cur.left
		}
	}
	if len(cur.rules) > 0 {
		acc = append(acc, cur.rules...)
	}
	return acc
}

// CompiledSet is an immutable, pre-indexed view of a rule set for fast path.
type CompiledSet struct {
	exact     map[string][]*Rule // domain exact (lowercased)
	suffix    *suffixTrie
	cidr      *cidrTree
	ipExact   map[[16]byte][]*Rule
	linear    []*Rule // ip/sni/dns/proto/asn/port/category matchers
	byID      map[string]*Rule
	ruleCount int
}

// Compile builds an immutable CompiledSet from rules.
func Compile(rs []*Rule) *CompiledSet {
	c := &CompiledSet{
		exact:   map[string][]*Rule{},
		suffix:  newSuffixTrie(),
		cidr:    &cidrTree{},
		ipExact: map[[16]byte][]*Rule{},
		byID:    map[string]*Rule{},
	}
	for _, r := range rs {
		if !r.Enabled {
			continue
		}
		c.byID[r.ID] = r
		if r.Kind == KindBlock && r.Category != "" {
			// category rules are matched via linear scan by category
			c.linear = append(c.linear, r)
			continue
		}
		c.ruleCount++
		for _, m := range r.Matchers {
			switch m.Field {
			case FieldDomain:
				c.exact[normalize(m.Value)] = append(c.exact[normalize(m.Value)], r)
			case FieldDomainSfx, FieldWildcard:
				sfx := trimStar(m.Value)
				c.suffix.insert(sfx, r)
			case FieldIP:
				if ip := net.ParseIP(m.Value); ip != nil {
					if v4 := ip.To4(); v4 != nil {
						var key [16]byte
						copy(key[0:4], v4)
						c.ipExact[key] = append(c.ipExact[key], r)
					} else {
						var key [16]byte
						key_to(&key, ip)
						c.ipExact[key] = append(c.ipExact[key], r)
					}
				}
			case FieldCIDR:
				_, ipnet, err := net.ParseCIDR(m.Value)
				if err == nil {
					ones, bits := ipnet.Mask.Size()
					if bits == 32 {
						var p [4]byte
						copy(p[:], ipnet.IP.To4())
						c.cidr.insert4(p, ones, r)
					} else {
						var p [16]byte
						copy(p[:], ipnet.IP.To16())
						c.cidr.insert6(p, ones, r)
					}
				}
			default:
				c.linear = append(c.linear, r)
			}
		}
	}
	return c
}

func normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func trimStar(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if strings.HasPrefix(p, "*.") {
		return p[2:]
	}
	if strings.HasPrefix(p, "*") {
		return p[1:]
	}
	return p
}

func key_to(key *[16]byte, ip net.IP) { copy(key[:], ip.To16()[:16]) }

// RuleCount returns the number of compiled matcher-bearing rules.
func (c *CompiledSet) RuleCount() int { return c.ruleCount }

// Rule returns a rule by id.
func (c *CompiledSet) Rule(id string) (*Rule, bool) { r, ok := c.byID[id]; return r, ok }

// Eval evaluates a decision for the given attributes using a strict priority:
// explicit allow > explicit block > category rule > default.
// Returns matched rules for scoring (most specific wins by order).
func (c *CompiledSet) Eval(a *Attributes) (*Decision, []*Rule) {
	var allow []*Rule
	var block []*Rule
	var category []*Rule
	var others []*Rule

	seen := map[*Rule]bool{}

	// exact / suffix / cidr / ip matches
	dom := normalize(a.Domain)
	if dom != "" {
		for _, r := range c.exact[dom] {
			classifyRule(r, a, &allow, &block, &category, &others, seen)
		}
		for _, r := range c.suffix.lookup(dom) {
			classifyRule(r, a, &allow, &block, &category, &others, seen)
		}
	}
	if a.DstIP != nil {
		if v4 := a.DstIP.To4(); v4 != nil {
			var key [16]byte
			copy(key[0:4], v4)
			for _, r := range c.ipExact[key] {
				classifyRule(r, a, &allow, &block, &category, &others, seen)
			}
			var ip [4]byte
			copy(ip[:], v4)
			for _, r := range c.cidr.lookup4(ip) {
				classifyRule(r, a, &allow, &block, &category, &others, seen)
			}
		} else {
			var ip6 [16]byte
			copy(ip6[:], a.DstIP.To16())
			for _, r := range c.ipExact[ip6] {
				classifyRule(r, a, &allow, &block, &category, &others, seen)
			}
			for _, r := range c.cidr.lookup6(ip6) {
				classifyRule(r, a, &allow, &block, &category, &others, seen)
			}
		}
	}
	// linear matchers
	for _, r := range c.linear {
		if seen[r] {
			continue
		}
		if ruleMatches(r, a) {
			classifyRule(r, a, &allow, &block, &category, &others, seen)
		}
	}

	// priority: explicit allow > explicit block > category > others(default by kind order)
	if len(allow) > 0 {
		return pick(allow), allow
	}
	if len(block) > 0 {
		return pick(block), block
	}
	if len(category) > 0 {
		return pick(category), category
	}
	if len(others) > 0 {
		return pick(others), others
	}
	return nil, nil
}

// Buckets is the result of rule evaluation split by priority layer, so callers
// (decision trace / explain) can see exactly which layer overrode which.
type Buckets struct {
	Allow    []*Rule
	Block    []*Rule
	Category []*Rule
	Others   []*Rule
	Decision *Decision // winning decision (nil when no rule matched)
}

// Layer returns the winning layer key ("allow","block","category","others") or
// "" when no rule matched.
func (b *Buckets) Layer() string {
	switch {
	case len(b.Allow) > 0:
		return "allow"
	case len(b.Block) > 0:
		return "block"
	case len(b.Category) > 0:
		return "category"
	case len(b.Others) > 0:
		return "others"
	}
	return ""
}

// EvalBuckets evaluates against the compiled set but preserves each priority
// layer separately. Like Eval, it obeys allow > block > category > others.
func (c *CompiledSet) EvalBuckets(a *Attributes) *Buckets {
	b := &Buckets{}
	c.collect(a, &b.Allow, &b.Block, &b.Category, &b.Others)
	switch {
	case len(b.Allow) > 0:
		b.Decision = pick(b.Allow)
	case len(b.Block) > 0:
		b.Decision = pick(b.Block)
	case len(b.Category) > 0:
		b.Decision = pick(b.Category)
	case len(b.Others) > 0:
		b.Decision = pick(b.Others)
	}
	return b
}

// collect is the shared matcher walk used by Eval and EvalBuckets.
func (c *CompiledSet) collect(a *Attributes, allow, block, category, others *[]*Rule) {
	seen := map[*Rule]bool{}
	dom := normalize(a.Domain)
	if dom != "" {
		for _, r := range c.exact[dom] {
			classifyRule(r, a, allow, block, category, others, seen)
		}
		for _, r := range c.suffix.lookup(dom) {
			classifyRule(r, a, allow, block, category, others, seen)
		}
	}
	if a.DstIP != nil {
		if v4 := a.DstIP.To4(); v4 != nil {
			var key [16]byte
			copy(key[0:4], v4)
			for _, r := range c.ipExact[key] {
				classifyRule(r, a, allow, block, category, others, seen)
			}
			var ip [4]byte
			copy(ip[:], v4)
			for _, r := range c.cidr.lookup4(ip) {
				classifyRule(r, a, allow, block, category, others, seen)
			}
		} else {
			var ip6 [16]byte
			copy(ip6[:], a.DstIP.To16())
			for _, r := range c.ipExact[ip6] {
				classifyRule(r, a, allow, block, category, others, seen)
			}
			for _, r := range c.cidr.lookup6(ip6) {
				classifyRule(r, a, allow, block, category, others, seen)
			}
		}
	}
	for _, r := range c.linear {
		if seen[r] {
			continue
		}
		if ruleMatches(r, a) {
			classifyRule(r, a, allow, block, category, others, seen)
		}
	}
}

func classifyRule(r *Rule, a *Attributes, allow, block, category, others *[]*Rule, seen map[*Rule]bool) {
	if seen[r] {
		return
	}
	seen[r] = true
	switch r.Kind {
	case KindAllow:
		*allow = append(*allow, r)
	case KindBlock:
		if r.Category != "" {
			*category = append(*category, r)
		} else {
			*block = append(*block, r)
		}
	case KindObserve, KindRateLimit:
		*others = append(*others, r)
	}
}

// pick returns the rule with the fewest matchers (most specific).
func pick(rs []*Rule) *Decision {
	best := rs[0]
	for _, r := range rs[1:] {
		if len(r.Matchers) < len(best.Matchers) {
			best = r
		} else if len(r.Matchers) == len(best.Matchers) && r.LastHit.After(best.LastHit) {
			best = r
		}
	}
	return &Decision{Action: string(best.Kind), MatchedRule: best.Label(), Category: best.Category}
}

// ruleMatches evaluates a rule's matchers against attributes (linear scan).
func ruleMatches(r *Rule, a *Attributes) bool {
	if len(r.Matchers) == 0 {
		return false
	}
	if r.Category != "" && r.Kind == KindBlock {
		// category rules match on attributes category (or tags).
		return strequals(a.Category, r.Category)
	}
	for _, m := range r.Matchers {
		switch m.Field {
		case FieldDomain, FieldDomainSfx, FieldWildcard:
			if a.Domain != "" && m.MatchesDomain(a.Domain) {
				continue
			}
			return false
		case FieldSNI:
			if !strequals(a.SNI, m.Value) {
				return false
			}
		case FieldDNS:
			if a.Domain == "" || !strequals(a.Domain, m.Value) {
				return false
			}
		case FieldProtocol:
			if !strequals(a.Proto, m.Value) {
				return false
			}
		case FieldPort:
			p, err := strconv.Atoi(m.Value)
			if err != nil || (a.DstPort != uint16(p) && a.SrcPort != uint16(p)) {
				return false
			}
		case FieldIP:
			if a.DstIP == nil || !a.DstIP.Equal(net.ParseIP(m.Value)) {
				return false
			}
		case FieldCIDR, FieldASN:
			// handled by tree/ASN tables; ASN fallback to nothing here.
			return false
		case Field("category"):
			if !strequals(a.Category, m.Value) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func strequals(a, b string) bool { return strings.EqualFold(a, b) }

// RuleRepo is a thread-safe, mutable rule store with hit accounting.
type RuleRepo struct {
	mu       sync.RWMutex
	rules    []*Rule
	compiled *CompiledSet
	// compileds map for refresh signals
	compiledCh chan struct{}
}

// NewRepo returns an empty repo.
func NewRepo() *RuleRepo {
	r := &RuleRepo{compiledCh: make(chan struct{}, 1)}
	r.Replace(nil)
	return r
}

// Replace atomically swaps the rule set and recompiles the lookup indexes.
func (r *RuleRepo) Replace(rs []*Rule) {
	if rs == nil {
		rs = []*Rule{}
	}
	compiled := Compile(rs)
	r.mu.Lock()
	r.rules = rs
	r.compiled = compiled
	r.mu.Unlock()
	select {
	case r.compiledCh <- struct{}{}:
	default:
	}
}

// All returns a snapshot of rules.
func (r *RuleRepo) All() []*Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Rule, len(r.rules))
	copy(out, r.rules)
	return out
}

// Get returns one rule by id.
func (r *RuleRepo) Get(id string) (*Rule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, x := range r.rules {
		if x.ID == id {
			return x, true
		}
	}
	return nil, false
}

// Add appends a new rule after validation.
func (r *RuleRepo) Add(rule *Rule) error {
	if rule.ID == "" {
		rule.ID = NewID("rule")
	}
	if err := rule.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	r.rules = append(r.rules, rule)
	r.compiled = Compile(r.rules)
	r.mu.Unlock()
	r.bump()
	return nil
}

// Update edits a rule in place.
func (r *RuleRepo) Update(rule *Rule) error {
	if err := rule.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, x := range r.rules {
		if x.ID == rule.ID {
			r.rules[i] = rule
			r.compiled = Compile(r.rules)
			r.bump()
			return nil
		}
	}
	return ErrNotFound
}

// Delete removes a rule by id.
func (r *RuleRepo) Delete(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, x := range r.rules {
		if x.ID == id {
			r.rules = append(r.rules[:i], r.rules[i+1:]...)
			r.compiled = Compile(r.rules)
			r.bump()
			return nil
		}
	}
	return ErrNotFound
}

// Eval runs matching against current rules.
func (r *RuleRepo) Eval(a *Attributes) (*Decision, []*Rule) {
	r.mu.RLock()
	compiled := r.compiled
	r.mu.RUnlock()
	return compiled.Eval(a)
}

// EvalBuckets runs matching against current rules, preserving priority layers.
func (r *RuleRepo) EvalBuckets(a *Attributes) *Buckets {
	r.mu.RLock()
	compiled := r.compiled
	r.mu.RUnlock()
	return compiled.EvalBuckets(a)
}

// ConflictsBetween returns rule pairs from `other` that conflict with rules in
// the current set (used by trace to surface skipped/overridden rules).
func (r *RuleRepo) ConflictsBetween(other []*Rule) []*Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*Rule
	for _, o := range other {
		for _, cur := range r.rules {
			if ok, _ := o.ConflictsWith(cur); ok {
				out = append(out, cur)
				break
			}
		}
	}
	return out
}

// RecordHit increments hit counter for matched rule ids.
func (r *RuleRepo) RecordHit(ids []*Rule) {
	if len(ids) == 0 {
		return
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, idref := range ids {
		for _, x := range r.rules {
			if x.ID == idref.ID {
				x.Hits++
				x.LastHit = now
				break
			}
		}
	}
	// avoid recompiling every hit: hits don't affect matching
}

// Conflicts returns conflicts across the current set.
func (r *RuleRepo) Conflicts() []Conflict {
	return FindConflicts(r.All())
}

var ErrNotFound = errNotFound()

func errNotFound() error { return errNotFoundError{} }

type errNotFoundError struct{}

func (errNotFoundError) Error() string { return "rule not found" }

// bump signals a recompile waiters (rarely used).
func (r *RuleRepo) bump() {
	_ = r.compiledCh
}
