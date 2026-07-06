// Package policy implements keephippo's ACL policies: an HCL parser for
// `path "x" { capabilities = [...] }` rules and an evaluation engine that is
// default-deny, honors an explicit `deny`, prefers exact over glob matches, and
// gates sudo-protected paths. It is a clean-room implementation shaped like
// Vault's policy semantics.
package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// Capability is a permitted action on a path.
type Capability string

const (
	Create Capability = "create"
	Read   Capability = "read"
	Update Capability = "update"
	Delete Capability = "delete"
	List   Capability = "list"
	Sudo   Capability = "sudo"
	Deny   Capability = "deny"
)

var knownCaps = map[Capability]bool{
	Create: true, Read: true, Update: true, Delete: true, List: true, Sudo: true, Deny: true,
}

// Policy is a parsed, named ACL policy.
type Policy struct {
	Name  string
	Rules []*Rule
}

// Rule is a single path rule.
type Rule struct {
	Path         string
	Capabilities []Capability
	m            matcher
}

type policyFile struct {
	Paths []pathBlock `hcl:"path,block"`
}

type pathBlock struct {
	Path         string   `hcl:"path,label"`
	Capabilities []string `hcl:"capabilities,optional"`
	Remain       hcl.Body `hcl:",remain"` // tolerate allowed_parameters, ttls, etc.
}

// Parse parses HCL policy source into a Policy.
func Parse(name, src string) (*Policy, error) {
	p := hclparse.NewParser()
	f, diags := p.ParseHCL([]byte(src), name+".hcl")
	if diags.HasErrors() {
		return nil, fmt.Errorf("policy %q: %s", name, diags.Error())
	}
	var pf policyFile
	if diags := gohcl.DecodeBody(f.Body, nil, &pf); diags.HasErrors() {
		return nil, fmt.Errorf("policy %q: %s", name, diags.Error())
	}

	pol := &Policy{Name: name}
	for _, b := range pf.Paths {
		caps := make([]Capability, 0, len(b.Capabilities))
		for _, c := range b.Capabilities {
			cp := Capability(c)
			if !knownCaps[cp] {
				return nil, fmt.Errorf("policy %q: unknown capability %q on path %q", name, c, b.Path)
			}
			caps = append(caps, cp)
		}
		path := strings.TrimPrefix(b.Path, "/")
		pol.Rules = append(pol.Rules, &Rule{Path: path, Capabilities: caps, m: compile(path)})
	}
	return pol, nil
}

// --- matching ---

type matcher struct {
	raw        string
	prefix     bool     // pattern ends with '*'
	prefixText string   // literal before the trailing '*'
	hasPlus    bool     // pattern contains a '+' segment wildcard
	segs       []string // segments (with '+' markers), trailing '*' stripped
}

func compile(path string) matcher {
	m := matcher{raw: path, hasPlus: strings.Contains(path, "+")}
	body := path
	if strings.HasSuffix(body, "*") {
		m.prefix = true
		m.prefixText = strings.TrimSuffix(body, "*")
		body = m.prefixText
	}
	m.segs = strings.Split(body, "/")
	return m
}

func (m matcher) isExact() bool { return !m.prefix && !m.hasPlus }

func (m matcher) matches(path string) bool {
	switch {
	case !m.prefix && !m.hasPlus:
		return path == m.raw
	case m.prefix && !m.hasPlus:
		return strings.HasPrefix(path, m.prefixText)
	default:
		return plusMatch(m.segs, m.prefix, path)
	}
}

// plusMatch matches segment patterns containing '+' (single-segment wildcard),
// optionally with a trailing '*' (prefix on the remainder).
func plusMatch(pat []string, trailingStar bool, path string) bool {
	hs := strings.Split(path, "/")
	n := len(pat)
	for i := 0; i < n; i++ {
		ps := pat[i]
		if trailingStar && i == n-1 {
			rest := ""
			if i < len(hs) {
				rest = strings.Join(hs[i:], "/")
			}
			return strings.HasPrefix(rest, ps)
		}
		if i >= len(hs) {
			return false
		}
		if ps == "+" {
			if hs[i] == "" {
				return false
			}
			continue
		}
		if ps != hs[i] {
			return false
		}
	}
	if trailingStar {
		return true
	}
	return len(hs) == n
}

// --- ACL ---

type capSet map[Capability]struct{}

func (s capSet) has(c Capability) bool { _, ok := s[c]; return ok }

// ACL is the merged, compiled access-control list for a set of policies.
type ACL struct {
	root  bool
	exact map[string]capSet
	globs []globRule // sorted by specificity, most specific first
}

type globRule struct {
	m     matcher
	caps  capSet
	score int
}

// NewACL merges policies into a single evaluatable ACL. The presence of a
// policy named "root" grants unrestricted access.
func NewACL(policies []*Policy) *ACL {
	a := &ACL{exact: map[string]capSet{}}
	globByRaw := map[string]capSet{}

	for _, p := range policies {
		if p == nil {
			continue
		}
		if p.Name == "root" {
			a.root = true
		}
		for _, r := range p.Rules {
			var target capSet
			if r.m.isExact() {
				if a.exact[r.Path] == nil {
					a.exact[r.Path] = capSet{}
				}
				target = a.exact[r.Path]
			} else {
				if globByRaw[r.Path] == nil {
					globByRaw[r.Path] = capSet{}
				}
				target = globByRaw[r.Path]
			}
			for _, c := range r.Capabilities {
				target[c] = struct{}{}
			}
		}
	}

	for raw, cs := range globByRaw {
		a.globs = append(a.globs, globRule{m: compile(raw), caps: cs, score: specificity(raw)})
	}
	sort.Slice(a.globs, func(i, j int) bool { return a.globs[i].score > a.globs[j].score })
	return a
}

// specificity ranks a glob by the length of its literal prefix (longer = more
// specific). Exact patterns get a large bonus (they are stored separately, but
// this keeps the ordering intuitive).
func specificity(pattern string) int {
	if idx := strings.IndexAny(pattern, "*+"); idx >= 0 {
		return idx
	}
	return len(pattern) + 1000
}

// Root reports whether this ACL grants unrestricted access.
func (a *ACL) Root() bool { return a.root }

func (a *ACL) capabilities(path string) capSet {
	if c, ok := a.exact[path]; ok {
		return c
	}
	for _, g := range a.globs {
		if g.m.matches(path) {
			return g.caps
		}
	}
	return nil
}

// Allowed reports whether cap is granted on path (default-deny; an explicit
// deny always wins).
func (a *ACL) Allowed(path string, cap Capability) bool {
	if a.root {
		return true
	}
	cs := a.capabilities(path)
	if cs == nil || cs.has(Deny) {
		return false
	}
	return cs.has(cap)
}

// HasSudo reports whether sudo is granted on path.
func (a *ACL) HasSudo(path string) bool {
	if a.root {
		return true
	}
	cs := a.capabilities(path)
	return cs != nil && !cs.has(Deny) && cs.has(Sudo)
}

// Capabilities returns the sorted capability names granted on path, matching
// Vault's sys/capabilities response (["root"], ["deny"], or the granted set).
func (a *ACL) Capabilities(path string) []string {
	if a.root {
		return []string{"root"}
	}
	cs := a.capabilities(path)
	if cs == nil || cs.has(Deny) {
		return []string{"deny"}
	}
	out := make([]string, 0, len(cs))
	for c := range cs {
		out = append(out, string(c))
	}
	if len(out) == 0 {
		return []string{"deny"}
	}
	sort.Strings(out)
	return out
}
