package blstkit

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Access structures for ciphertext-policy ABE: a monotone boolean formula as a threshold tree.
//
//	{attr}                      leaf
//	{allOf: [...]}              AND (n-of-n)
//	{anyOf: [...]}              OR  (1-of-n)
//	{threshold: k, of: [...]}   k-of-n

const (
	abeMaxPolicyNodes = 1024
	// abeMaxPolicyDepth bounds gate nesting so that "encryptable" implies "decryptable" under the canonical JSON depth cap.
	abeMaxPolicyDepth = 10
)

// abeTree is the normalised form: every interior node is an explicit t-of-n gate.
type abeTree struct {
	leaf bool
	attr string
	t    int
	of   []*abeTree
}

// toJSON is the wire form {kind:"leaf",attr} / {kind:"gate",t,of}.
func (n *abeTree) toJSON() map[string]any {
	if n.leaf {
		return map[string]any{"kind": "leaf", "attr": n.attr}
	}
	of := make([]any, len(n.of))
	for i, c := range n.of {
		of[i] = c.toJSON()
	}
	return map[string]any{"kind": "gate", "t": json.Number(strconv.Itoa(n.t)), "of": of}
}

func (n *abeTree) leafCount() int {
	if n.leaf {
		return 1
	}
	c := 0
	for _, k := range n.of {
		c += k.leafCount()
	}
	return c
}

func (n *abeTree) leafAttrs(out *[]string) {
	if n.leaf {
		*out = append(*out, n.attr)
		return
	}
	for _, k := range n.of {
		k.leafAttrs(out)
	}
}

// firstRepeatedAttribute is the first attribute named by two leaves ("" when none; attributes are non-empty).
func (n *abeTree) firstRepeatedAttribute() string {
	var attrs []string
	n.leafAttrs(&attrs)
	seen := map[string]bool{}
	for _, a := range attrs {
		if seen[a] {
			return a
		}
		seen[a] = true
	}
	return ""
}

func (n *abeTree) satisfies(has func(string) bool) bool {
	if n.leaf {
		return has(n.attr)
	}
	met := 0
	for _, c := range n.of {
		if c.satisfies(has) {
			met++
		}
	}
	return met >= n.t
}

// isIllFormedUTF16 reports whether s holds an unpaired UTF-16 surrogate (kept as its WTF-8 form by the lenient parser) or is
// not valid UTF-8: such strings alias each other once UTF-8 encoded.
func isIllFormedUTF16(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == 0xED && s[i+1] >= 0xA0 {
			return true
		}
	}
	return !isValidUTF8(s)
}

func isValidUTF8(s string) bool { return utf8.ValidString(s) }

// jsFloat reads a JSON number.
func jsFloat(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := strconv.ParseFloat(n.String(), 64)
	return f, err == nil
}

// isPosInt: a JSON number that is a positive integer (JavaScript Number.isInteger semantics).
func isPosInt(v any) (float64, bool) {
	f, ok := jsFloat(v)
	return f, ok && f > 0 && f == math.Trunc(f) && !math.IsInf(f, 0)
}

func isNum(v any, want float64) bool {
	f, ok := jsFloat(v)
	return ok && f == want
}

func fmtNum(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// abeNormalizePolicy validates and normalises an access structure; on failure it returns the reason (fails closed on any
// malformed node, empty gate, out-of-range threshold or oversized tree).
func abeNormalizePolicy(policy any) (*abeTree, string) {
	nodes := 0
	var walk func(p any, path string, gates int) (*abeTree, string)
	walk = func(p any, path string, gates int) (*abeTree, string) {
		nodes++
		if nodes > abeMaxPolicyNodes {
			return nil, fmt.Sprintf("policy too large (> %d nodes)", abeMaxPolicyNodes)
		}
		m, ok := p.(map[string]any)
		if !ok {
			return nil, path + ": not an object"
		}
		has := func(k string) bool { _, ok := m[k]; return ok }
		if has("attr") {
			s, ok := m["attr"].(string)
			if !ok || s == "" {
				return nil, path + ": 'attr' must be a non-empty string"
			}
			if isIllFormedUTF16(s) {
				return nil, path + ": 'attr' is not well-formed UTF-16"
			}
			if has("allOf") || has("anyOf") || has("threshold") || has("of") {
				return nil, path + ": a leaf must not mix 'attr' with a gate"
			}
			return &abeTree{leaf: true, attr: s}, ""
		}
		var gateKeys []string
		for _, k := range []string{"allOf", "anyOf", "threshold", "of"} {
			if has(k) && (k != "of" || !has("threshold")) {
				gateKeys = append(gateKeys, k)
			}
		}
		if len(gateKeys) > 1 {
			return nil, fmt.Sprintf("%s: ambiguous node (%s); a gate must use exactly one of allOf/anyOf/threshold", path, strings.Join(gateKeys, ", "))
		}
		if len(gateKeys) == 1 && gates+1 > abeMaxPolicyDepth {
			return nil, fmt.Sprintf("%s: policy nested deeper than %d gates", path, abeMaxPolicyDepth)
		}
		children := func(raw any, key string) ([]*abeTree, string) {
			l, ok := raw.([]any)
			if !ok || len(l) == 0 {
				return nil, fmt.Sprintf("%s: '%s' must be a non-empty array", path, key)
			}
			out := make([]*abeTree, 0, len(l))
			for i, c := range l {
				k, why := walk(c, fmt.Sprintf("%s.%s[%d]", path, key, i), gates+1)
				if why != "" {
					return nil, why
				}
				out = append(out, k)
			}
			return out, ""
		}
		switch {
		case has("allOf"):
			kids, why := children(m["allOf"], "allOf")
			if why != "" {
				return nil, why
			}
			return &abeTree{t: len(kids), of: kids}, ""
		case has("anyOf"):
			kids, why := children(m["anyOf"], "anyOf")
			if why != "" {
				return nil, why
			}
			return &abeTree{t: 1, of: kids}, ""
		case has("threshold"):
			f, ok := isPosInt(m["threshold"])
			if !ok {
				return nil, path + ": 'threshold' must be a positive integer"
			}
			kids, why := children(m["of"], "of")
			if why != "" {
				return nil, why
			}
			if f > float64(len(kids)) {
				return nil, fmt.Sprintf("%s: threshold %s exceeds the number of branches (%d)", path, fmtNum(f), len(kids))
			}
			return &abeTree{t: int(f), of: kids}, ""
		}
		return nil, path + ": unknown policy node (expected attr/allOf/anyOf/threshold)"
	}
	tree, why := walk(policy, "policy", 0)
	if why != "" {
		return nil, why
	}
	return tree, ""
}

// AbeNormalizePolicy validates a policy and returns the normalised tree ({kind:"leaf",attr} / {kind:"gate",t,of}), or the
// reason it was refused.
func AbeNormalizePolicy(policy any) (tree map[string]any, reason string) {
	t, why := abeNormalizePolicy(policy)
	if why != "" {
		return nil, why
	}
	return t.toJSON(), ""
}

// abeParseTree validates an untrusted ciphertext tree (nil on any deviation); a bounded node budget limits the work.
func abeParseTree(x any, gates int, nodes *int) *abeTree {
	*nodes++
	m, ok := x.(map[string]any)
	if *nodes > abeMaxPolicyNodes || !ok {
		return nil
	}
	switch m["kind"] {
	case "leaf":
		attr, ok := m["attr"].(string)
		if !ok || attr == "" || isIllFormedUTF16(attr) || len(m) != 2 {
			return nil
		}
		return &abeTree{leaf: true, attr: attr}
	case "gate":
		if gates+1 > abeMaxPolicyDepth || len(m) != 3 {
			return nil
		}
		tf, ok := isPosInt(m["t"])
		of, ok2 := m["of"].([]any)
		if !ok || !ok2 || len(of) == 0 || tf > float64(len(of)) || len(of) >= abeMaxPolicyNodes {
			return nil
		}
		kids := make([]*abeTree, 0, len(of))
		for _, b := range of {
			sub := abeParseTree(b, gates+1, nodes)
			if sub == nil {
				return nil
			}
			kids = append(kids, sub)
		}
		return &abeTree{t: int(tf), of: kids}
	}
	return nil
}

// AbeSatisfies is the pure, non-cryptographic check (a convenience / test oracle) that the attribute set satisfies the tree.
func AbeSatisfies(tree map[string]any, attrs []string) bool {
	nodes := 0
	t := abeParseTree(tree, 0, &nodes)
	if t == nil {
		return false
	}
	set := map[string]bool{}
	for _, a := range attrs {
		set[a] = true
	}
	return t.satisfies(func(a string) bool { return set[a] })
}

// AbePolicyAttributes lists every attribute named by the tree, sorted.
func AbePolicyAttributes(tree map[string]any) []string {
	nodes := 0
	t := abeParseTree(tree, 0, &nodes)
	if t == nil {
		return nil
	}
	var attrs []string
	t.leafAttrs(&attrs)
	set := map[string]bool{}
	var out []string
	for _, a := range attrs {
		if !set[a] {
			set[a] = true
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}
