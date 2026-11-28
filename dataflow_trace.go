package pca

// Trace rules: "never B after A within <window>" guardrails (the toxic-flow shape of Invariant Labs' guardrails) lowered to
// derive caveats that every verifier evaluates over its own signed action history. A caveat only removes authority, so a
// compiled rule is a restriction by construction. Compilation is fail-strict: anything the target cannot express exactly
// is a *CodedError, never skipped. LethalTrifecta is a lint over a verb table and the compiled edges.

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// MaxTraceCaveats bounds one compiled rule set.
const MaxTraceCaveats = 64

const traceBChunk = 8 // 7 + 3k expression nodes stay within the derive node budget

// TraceSelector names actions: tools, traits, resource prefixes (earlier side only) or any.
type TraceSelector struct {
	Tools     []string `json:"tools"`
	Traits    []string `json:"traits"`
	Resources []string `json:"resources"`
	Any       bool     `json:"any"`
}

// TraceRule is one "never Never after After within WithinMs" rule.
type TraceRule struct {
	ID       string        `json:"id"`
	Never    TraceSelector `json:"never"`
	After    TraceSelector `json:"after"`
	WithinMs int64         `json:"within_ms"`
	Reason   *string       `json:"reason,omitempty"`
}

// VerbDef is a verb's effective traits and effects.
type VerbDef struct {
	Traits  []string `json:"traits"`
	Effects []string `json:"effects,omitempty"`
}

// VerbTable maps a verb to its definition.
type VerbTable map[string]VerbDef

// TraceEdgeFrom is the earlier side of an edge: a tool or a resource prefix.
type TraceEdgeFrom struct {
	Tool     *string `json:"tool,omitempty"`
	Resource *string `json:"resource,omitempty"`
}

// TraceEdge records that rule forbids To within WithinMs after From.
type TraceEdge struct {
	Rule     string        `json:"rule"`
	From     TraceEdgeFrom `json:"from"`
	To       string        `json:"to"`
	WithinMs int64         `json:"within_ms"`
}

// CompiledTrace is the lowered rule set; Digest = hashCanonical({d: "atlas-pca/trace-rules/v1", caveats}).
type CompiledTrace struct {
	Caveats []map[string]any `json:"caveats"`
	Edges   []TraceEdge      `json:"edges"`
	Digest  string           `json:"digest"`
}

// InvariantImport is an imported Invariant rule plus the conditions dropped under DropUnsupported.
type InvariantImport struct {
	Rule    TraceRule `json:"rule"`
	Dropped []string  `json:"dropped"`
}

// InvariantOptions: Horizon (a duration like 7d) is required; DropUnsupported removes conjuncts (more refusals, never fewer).
type InvariantOptions struct {
	Horizon         string
	DropUnsupported bool
}

// JS regular-expression classes: \s (Unicode white space) and . (anything but a line terminator).
const (
	jsReS   = `[\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]`
	jsReNS  = `[^\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]`
	jsReDot = `[^\n\r\x{2028}\x{2029}]`
)

var (
	traceRuleIDRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
	traceVerbRe   = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,256}$`)
	traceDurRe    = regexp.MustCompile(`^([1-9][0-9]{0,9})(ms|s|m|h|d)$`)
	traceRuleRe   = regexp.MustCompile(`^` + jsReS + `*never` + jsReS + `+(` + jsReDot + `+?)` + jsReS + `+after` + jsReS + `+(` + jsReDot + `+?)` + jsReS + `+within` + jsReS + `+(` + jsReNS + `+)` + jsReS + `*$`)
	invHeadRe     = regexp.MustCompile(`^raise` + jsReS + `+(?:"([^"]*)"|'([^']*)')` + jsReS + `+if:$`)
	invFlowRe     = regexp.MustCompile(`^\((\w+):` + jsReS + `*(ToolCall|ToolOutput|Message)\)` + jsReS + `*->` + jsReS + `*\((\w+):` + jsReS + `*(ToolCall|ToolOutput|Message)\)$`)
	invIsRe       = regexp.MustCompile(`^(\w+)` + jsReS + `+is` + jsReS + `+tool:([A-Za-z0-9_.:/-]+)(\(` + jsReDot + `*\))?$`)
	traceUnit     = map[string]int64{"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}
)

func traceErr(code, msg string) error { return &CodedError{Code: code, Msg: msg} }

func traceDuration(t string) (int64, error) {
	m := traceDurRe.FindStringSubmatch(t)
	if m == nil {
		return 0, traceErr("duration", "'"+t+"' is not a duration like 10m, 2h or 7d")
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	ms := n * traceUnit[m[2]]
	if ms > DeriveMaxWindowMs {
		return 0, traceErr("window", "a window of "+t+" exceeds the 30-day history the verifier keeps")
	}
	return ms, nil
}

func newTraceSelector() TraceSelector {
	return TraceSelector{Tools: []string{}, Traits: []string{}, Resources: []string{}}
}

func traceSelector(text string, never bool) (TraceSelector, error) {
	s := newTraceSelector()
	for _, raw := range strings.Split(text, ",") {
		a := jsTrim(raw)
		switch {
		case a == "any":
			s.Any = true
		case strings.HasPrefix(a, "tool:") && traceVerbRe.MatchString(a[5:]):
			s.Tools = append(s.Tools, a[5:])
		case strings.HasPrefix(a, "trait:") && traceVerbRe.MatchString(a[6:]):
			s.Traits = append(s.Traits, a[6:])
		case strings.HasPrefix(a, "resource:") && jsLen(a) > 9 && jsLen(a) <= 9+256:
			if never {
				return s, traceErr("resource_on_effect", "a resource selector can only name the earlier action (the check reads the current verb)")
			}
			s.Resources = append(s.Resources, a[9:])
		default:
			return s, traceErr("selector", "'"+a+"' is not tool:<verb>, trait:<id>, resource:<prefix> or any")
		}
	}
	return s, nil
}

func traceIDErr(id string) error {
	return traceErr("id", "rule id '"+id+"' must match ^[a-z][a-z0-9_]{0,39}$")
}

// ParseTraceRule parses `never <B> after <A> within <duration>`; reason nil is absent.
func ParseTraceRule(id, text string, reason *string) (*TraceRule, error) {
	if !traceRuleIDRe.MatchString(id) {
		return nil, traceIDErr(id)
	}
	m := traceRuleRe.FindStringSubmatch(text)
	if m == nil {
		return nil, traceErr("syntax", "expected 'never <selector> after <selector> within <duration>', got '"+text+"'")
	}
	nv, err := traceSelector(m[1], true)
	if err != nil {
		return nil, err
	}
	af, err := traceSelector(m[2], false)
	if err != nil {
		return nil, err
	}
	w, err := traceDuration(m[3])
	if err != nil {
		return nil, err
	}
	return &TraceRule{ID: id, Never: nv, After: af, WithinMs: w, Reason: reason}, nil
}

// ParseInvariantRule imports `raise "<msg>" if: (x: ToolCall|ToolOutput) -> (y: ToolCall)` plus `x is tool:<name>` lines.
func ParseInvariantRule(id, text string, o InvariantOptions) (*InvariantImport, error) {
	if !traceRuleIDRe.MatchString(id) {
		return nil, traceIDErr(id)
	}
	if o.Horizon == "" {
		return nil, traceErr("horizon", "an Invariant rule has no window: pass the horizon explicitly")
	}
	within, err := traceDuration(o.Horizon)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(text, "\n") {
		if l = jsTrim(l); l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	line := func(i int) string {
		if i < len(lines) {
			return lines[i]
		}
		return ""
	}
	head := invHeadRe.FindStringSubmatchIndex(line(0))
	if head == nil {
		return nil, traceErr("syntax", `the first line must be raise "<message>" if:`)
	}
	flow := invFlowRe.FindStringSubmatch(line(1))
	if flow == nil {
		return nil, traceErr("unsupported", "the second line must be one flow '(x: ToolCall|ToolOutput) -> (y: ToolCall)' (chains of three and other patterns are not supported)")
	}
	a, ta, b, tb := flow[1], flow[2], flow[3], flow[4]
	if ta == "Message" || tb != "ToolCall" {
		return nil, traceErr("unsupported", "only a tool call or tool output followed by a tool call can be compiled")
	}
	if a == b {
		return nil, traceErr("syntax", "the two events need distinct names")
	}
	tools := map[string][]string{a: {}, b: {}}
	dropped := []string{}
	for _, l := range lines[min(2, len(lines)):] {
		m := invIsRe.FindStringSubmatchIndex(l)
		var name, tool string
		known, hasArgs := false, false
		if m != nil {
			name, tool = l[m[2]:m[3]], l[m[4]:m[5]]
			_, known = tools[name]
			hasArgs = m[6] >= 0
		}
		if known && !hasArgs {
			tools[name] = append(tools[name], tool)
			continue
		}
		if o.DropUnsupported {
			if known { // the argument pattern is dropped, the tool kept: a wider match, so more refusals
				tools[name] = append(tools[name], tool)
			}
			dropped = append(dropped, l)
			continue
		}
		return nil, traceErr("unsupported", "'"+l+"' is outside the compilable subset (x is tool:<name>); pass dropUnsupported to refuse more instead")
	}
	for _, v := range []string{a, b} {
		if len(tools[v]) > 1 {
			return nil, traceErr("unsatisfiable", "'"+v+"' is constrained to two different tools, so the rule can never fire")
		}
	}
	sel := func(v string) TraceSelector {
		s := newTraceSelector()
		s.Tools, s.Any = tools[v], len(tools[v]) == 0
		return s
	}
	h0 := line(0)
	reason := ""
	if head[2] >= 0 {
		reason = h0[head[2]:head[3]]
	} else if head[4] >= 0 {
		reason = h0[head[4]:head[5]]
	}
	return &InvariantImport{Rule: TraceRule{ID: id, Never: sel(b), After: sel(a), WithinMs: within, Reason: &reason}, Dropped: dropped}, nil
}

func traceExpand(s TraceSelector, table VerbTable, what string) ([]string, error) {
	verbs := make([]string, 0, len(table))
	for v := range table {
		verbs = append(verbs, v)
	}
	verbs = jsSortStrings(verbs)
	out := map[string]bool{}
	if s.Any {
		for _, v := range verbs {
			out[v] = true
		}
	}
	for _, t := range s.Tools {
		if _, ok := table[t]; !ok {
			return nil, traceErr("unknown_tool", what+": tool '"+t+"' is not an action in the verb table")
		}
		out[t] = true
	}
	for _, tr := range s.Traits {
		hit := false
		for _, v := range verbs {
			if containsStr(table[v].Traits, tr) {
				out[v], hit = true, true
			}
		}
		if !hit {
			return nil, traceErr("empty_selector", what+": trait '"+tr+"' matches no action")
		}
	}
	l := make([]string, 0, len(out))
	for v := range out {
		l = append(l, v)
	}
	return jsSortStrings(l), nil
}

func i64Num(n int64) json.Number { return json.Number(strconv.FormatInt(n, 10)) }

// CompileTraceRules lowers rules to derive caveats over the verifier's history; anything not expressible is a *CodedError.
func CompileTraceRules(rules []TraceRule, table VerbTable) (*CompiledTrace, error) {
	caveats := []map[string]any{}
	edges := []TraceEdge{}
	ids := map[string]bool{}
	for _, r := range rules {
		if !traceRuleIDRe.MatchString(r.ID) || ids[r.ID] {
			return nil, traceErr("id", "rule id '"+r.ID+"' is malformed or repeated")
		}
		ids[r.ID] = true
		if r.WithinMs < 1 || r.WithinMs > DeriveMaxWindowMs {
			return nil, traceErr("window", "rule '"+r.ID+"': within_ms must be 1..30 days")
		}
		if len(r.Never.Resources) > 0 {
			return nil, traceErr("resource_on_effect", "rule '"+r.ID+"': a resource selector cannot name the later action")
		}
		bs, err := traceExpand(r.Never, table, "rule '"+r.ID+"' never")
		if err != nil {
			return nil, err
		}
		av, err := traceExpand(r.After, table, "rule '"+r.ID+"' after")
		if err != nil {
			return nil, err
		}
		type aSide struct {
			key, val string
		}
		as := make([]aSide, 0, len(av)+len(r.After.Resources))
		for _, v := range av {
			as = append(as, aSide{"verb", v})
		}
		for _, p := range jsSortStrings(distinct(r.After.Resources)) {
			as = append(as, aSide{"resource_prefix", p})
		}
		if len(bs) == 0 || len(as) == 0 {
			return nil, traceErr("empty_selector", "rule '"+r.ID+"': a side matches nothing")
		}
		n := 0
		for _, a := range as {
			for i := 0; i < len(bs); i += traceBChunk {
				chunk := bs[i:min(i+traceBChunk, len(bs))]
				or := make([]any, len(chunk))
				for j, v := range chunk {
					or[j] = map[string]any{"op": "eq", "a": map[string]any{"ref": "verb"}, "b": map[string]any{"const": v}}
				}
				c := map[string]any{
					"type": "derive",
					"id":   "trace." + r.ID + "." + strconv.Itoa(n),
					"defs": []any{
						map[string]any{"name": "seen", "kind": "count", "window_ms": i64Num(r.WithinMs), a.key: a.val},
						map[string]any{"name": "verb", "kind": "action", "field": "verb"},
						map[string]any{"name": "is_b", "kind": "expr", "expr": map[string]any{"op": "or", "args": or}},
					},
					// refused iff an A happened within the window AND this action is a B; unknown refuses too
					"check": map[string]any{"op": "not", "arg": map[string]any{"op": "and", "args": []any{
						map[string]any{"op": "gt", "a": map[string]any{"ref": "seen"}, "b": map[string]any{"const": json.Number("0")}},
						map[string]any{"ref": "is_b"},
					}}},
				}
				n++
				if e := DeriveError(c); e != "" {
					return nil, traceErr("internal", "rule '"+r.ID+"' compiled to an invalid caveat: "+e)
				}
				caveats = append(caveats, c)
				if len(caveats) > MaxTraceCaveats {
					return nil, traceErr("too_large", "more than "+strconv.Itoa(MaxTraceCaveats)+" caveats: split the rule set or narrow the selectors")
				}
			}
			for _, v := range bs {
				val := a.val
				from := TraceEdgeFrom{Tool: &val}
				if a.key != "verb" {
					from = TraceEdgeFrom{Resource: &val}
				}
				edges = append(edges, TraceEdge{Rule: r.ID, From: from, To: v, WithinMs: r.WithinMs})
			}
		}
	}
	cv := make([]any, len(caveats))
	for i, c := range caveats {
		cv[i] = c
	}
	d, err := HashCanonical(map[string]any{"d": "atlas-pca/trace-rules/v1", "caveats": cv})
	if err != nil {
		return nil, err
	}
	return &CompiledTrace{Caveats: caveats, Edges: edges, Digest: d}, nil
}

// PrivateReadTraits mean "reads private data"; ExternalSendTraits mean "can send data out".
var (
	PrivateReadTraits  = []string{"pca.pii_access", "pca.financial_data_read", "pca.credential_access", "pca.regulated_data"}
	ExternalSendTraits = []string{"pca.external_communication", "pca.network_egress", "pca.data_export", "pca.public_exposure"}
)

// TrifectaOptions names extra untrusted-content reads by verb or trait.
type TrifectaOptions struct {
	Untrusted       []string `json:"untrusted,omitempty"`
	UntrustedTraits []string `json:"untrusted_traits,omitempty"`
}

// TrifectaFinding is a send left open to both an untrusted read and a private read.
type TrifectaFinding struct {
	Send          string   `json:"send"`
	FromUntrusted []string `json:"from_untrusted"`
	FromPrivate   []string `json:"from_private"`
}

// TrifectaReport is the lethal-trifecta lint result.
type TrifectaReport struct {
	PrivateReads   []string          `json:"private_reads"`
	UntrustedReads []string          `json:"untrusted_reads"`
	Sends          []string          `json:"sends"`
	Findings       []TrifectaFinding `json:"findings"`
}

// LethalTrifecta reports sends reachable from both an untrusted read and a private read with no edge rule cutting either
// leg. A lint only: it reports, it does not enforce.
func LethalTrifecta(table VerbTable, edges []TraceEdge, o TrifectaOptions) TrifectaReport {
	verbs := make([]string, 0, len(table))
	for v := range table {
		verbs = append(verbs, v)
	}
	verbs = jsSortStrings(verbs)
	has := func(v string, ts []string) bool {
		for _, t := range table[v].Traits {
			if containsStr(ts, t) {
				return true
			}
		}
		return false
	}
	readOnly := func(v string) bool {
		e := table[v].Effects
		if len(e) == 0 {
			return false
		}
		for _, x := range e {
			if x != "read" {
				return false
			}
		}
		return true
	}
	priv, untrusted, sends := []string{}, []string{}, []string{}
	for _, v := range verbs {
		if has(v, PrivateReadTraits) {
			priv = append(priv, v)
		}
		if containsStr(o.Untrusted, v) || has(v, o.UntrustedTraits) || (readOnly(v) && containsStr(table[v].Traits, "pca.network_egress")) {
			untrusted = append(untrusted, v)
		}
		if has(v, ExternalSendTraits) && !readOnly(v) {
			sends = append(sends, v)
		}
	}
	findings := []TrifectaFinding{}
	if len(priv) > 0 && len(untrusted) > 0 && len(sends) > 0 {
		ruled := func(from, to string) bool {
			for _, e := range edges {
				if e.From.Tool != nil && *e.From.Tool == from && e.To == to {
					return true
				}
			}
			return false
		}
		for _, s := range sends {
			fu, fp := []string{}, []string{}
			for _, u := range untrusted {
				if !ruled(u, s) {
					fu = append(fu, u)
				}
			}
			for _, p := range priv {
				if !ruled(p, s) {
					fp = append(fp, p)
				}
			}
			if len(fu) > 0 && len(fp) > 0 {
				findings = append(findings, TrifectaFinding{Send: s, FromUntrusted: fu, FromPrivate: fp})
			}
		}
	}
	return TrifectaReport{PrivateReads: priv, UntrustedReads: untrusted, Sends: sends, Findings: findings}
}
