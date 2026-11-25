package pca

// Model Context Protocol adapter, the pure surface: the client half of MCP authorization step-up (the WWW-Authenticate parser, the
// step-up planner, the RFC 9207 iss table), the tool-result proof meta, the v1 action-schema draft from an MCP tool list with its
// decisions, and the closed-world check of a tool call. Every entry point takes and returns JSON values (as StrictParse /
// ParseJSONLenient produce them) and follows the reference's JavaScript semantics on hostile input; where the reference would throw
// (a null tool, a non-iterable `required`, a decision about a verb the draft lacks) the Go function returns an error.
//
// Not ported: the tool-handler wrapper and the per-call proof fetch (they need a live agent and a transport; RequirePCA and the
// agent's Act cover them), the optional action-kit importer, and the reference's provenance header (not produced natively).

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// McpClientRevisions are the MCP authorization revisions of the client conformance matrix.
var McpClientRevisions = []string{"2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28", "draft"}

func mcpLevels(a, b, c, d, e string) map[string]any {
	return map[string]any{"2025-03-26": a, "2025-06-18": b, "2025-11-25": c, "2026-07-28": d, "draft": e}
}

// McpAuthClientRows is the client-side MCP authorization conformance matrix (a fresh copy per call).
func McpAuthClientRows() []any {
	row := func(id, req string, levels map[string]any, section string) any {
		return map[string]any{"id": id, "requirement": req, "levels": levels, "section": section}
	}
	return []any{
		row("parse-www-authenticate", "Parse WWW-Authenticate headers (quoted strings, several challenges) and respond to 401.", mcpLevels("n/a", "MUST", "MUST", "MUST", "MUST"), "Protected Resource Metadata Discovery Requirements"),
		row("step-up-on-insufficient-scope", "Respond to 403 insufficient_scope by re-authorizing with an increased scope set.", mcpLevels("n/a", "n/a", "SHOULD", "SHOULD", "SHOULD"), "Step-Up Authorization Flow"),
		row("scope-union", "The new scope set is the union of the previously requested set and the challenge scopes.", mcpLevels("n/a", "n/a", "n/a", "SHOULD", "SHOULD"), "Step-Up Authorization Flow, step 2"),
		row("retry-limit", "Retry no more than a few times and track upgrade attempts per resource and operation.", mcpLevels("n/a", "n/a", "SHOULD", "SHOULD", "SHOULD"), "Step-Up Authorization Flow, step 4"),
		row("iss-validation-table", "Validate the RFC 9207 iss parameter against the recorded issuer, by the four-row table, with no normalization.", mcpLevels("n/a", "n/a", "n/a", "MUST", "MUST"), "Authorization Response Validation"),
		row("pca-need-ignored-by-stock-client", "A client that does not know pca_need behaves exactly as without it.", mcpLevels("EXT", "EXT", "EXT", "EXT", "EXT"), "RFC 9110 section 11.2 (unknown auth-params are ignored)"),
	}
}

// ---- JavaScript value helpers -----------------------------------------------------------------------------------------

type mcpUndefT struct{}

var mcpUnd any = mcpUndefT{} // JavaScript `undefined` (a JSON null stays nil)

func mcpIsUnd(x any) bool { _, ok := x.(mcpUndefT); return ok }

func mcpNullish(x any) bool { return x == nil || mcpIsUnd(x) }

// mcpGet is `o[k]` of a JSON value for an own member: undefined when absent or when o is not an object.
func mcpGet(o any, k string) any {
	if m, ok := o.(map[string]any); ok {
		if v, has := m[k]; has {
			return v
		}
	}
	return mcpUnd
}

// mcpTruthy is JavaScript truthiness of a JSON value (or undefined).
func mcpTruthy(x any) bool {
	switch t := x.(type) {
	case nil, mcpUndefT:
		return false
	case bool:
		return t
	case string:
		return t != ""
	}
	if f, ok := jsNum(x); ok {
		return f != 0 && !math.IsNaN(f)
	}
	return true
}

func mcpSafeInt(x any) (float64, bool) {
	f, ok := jsNum(x)
	if !ok || math.IsInf(f, 0) || math.IsNaN(f) || f != math.Trunc(f) || math.Abs(f) > 9007199254740991 {
		return 0, false
	}
	return f, true
}

// mcpUnitsToString encodes UTF-16 units to a string; a lone surrogate becomes its 3-byte WTF-8 form (as the strict parser keeps it).
func mcpUnitsToString(u []uint16) string {
	var sb strings.Builder
	for i := 0; i < len(u); i++ {
		c := rune(u[i])
		if c >= 0xD800 && c < 0xDC00 && i+1 < len(u) && u[i+1] >= 0xDC00 && u[i+1] < 0xE000 {
			sb.WriteRune(utf16.DecodeRune(c, rune(u[i+1])))
			i++
			continue
		}
		if c >= 0xD800 && c < 0xE000 {
			sb.WriteByte(byte(0xE0 | c>>12))
			sb.WriteByte(byte(0x80 | (c>>6)&0x3f))
			sb.WriteByte(byte(0x80 | c&0x3f))
			continue
		}
		sb.WriteRune(c)
	}
	return sb.String()
}

// mcpSliceUnits is `s.slice(0, n)` (UTF-16 code units).
func mcpSliceUnits(s string, n int) string {
	u := utf16Units(s)
	if len(u) <= n {
		return s
	}
	return mcpUnitsToString(u[:n])
}

// mcpIter is JavaScript iteration (`[...x]`, `new Set(x)`) of a JSON value: arrays, and strings by code point.
func mcpIter(x any) ([]any, error) {
	switch t := x.(type) {
	case []any:
		return t, nil
	case string:
		u := utf16Units(t)
		out := []any{}
		for i := 0; i < len(u); i++ {
			n := 1
			if u[i] >= 0xD800 && u[i] < 0xDC00 && i+1 < len(u) && u[i+1] >= 0xDC00 && u[i+1] < 0xE000 {
				n = 2
			}
			out = append(out, mcpUnitsToString(u[i:i+n]))
			i += n - 1
		}
		return out, nil
	}
	return nil, errors.New("value is not iterable")
}

// mcpKeys is Object.keys of a JSON value.
func mcpKeys(o any) []string {
	switch t := o.(type) {
	case map[string]any:
		ks := make([]string, 0, len(t))
		for k := range t {
			ks = append(ks, k)
		}
		sortUtf8(ks)
		return ks
	case []any:
		ks := make([]string, len(t))
		for i := range t {
			ks[i] = fmt.Sprint(i)
		}
		return ks
	case string:
		ks := make([]string, jsLen(t))
		for i := range ks {
			ks[i] = fmt.Sprint(i)
		}
		return ks
	}
	return nil
}

// mcpIndex is `o[k]` for a key from mcpKeys.
func mcpIndex(o any, k string) any {
	switch t := o.(type) {
	case map[string]any:
		return t[k]
	case []any:
		if n, ok := canonDec(k); ok && n < len(t) {
			return t[n]
		}
	case string:
		if n, ok := canonDec(k); ok {
			if u := utf16Units(t); n < len(u) {
				return mcpUnitsToString(u[n : n+1])
			}
		}
	}
	return nil
}

// mcpSpread is the object spread `{...x}` of a JSON value.
func mcpSpread(x any) map[string]any {
	out := map[string]any{}
	for _, k := range mcpKeys(x) {
		out[k] = mcpIndex(x, k)
	}
	return out
}

func mcpCopy(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// mcpJSStr is String(x) of a JSON value (or undefined).
func mcpJSStr(x any) string {
	switch t := x.(type) {
	case nil:
		return "null"
	case mcpUndefT:
		return "undefined"
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			if e != nil {
				parts[i] = mcpJSStr(e)
			}
		}
		return strings.Join(parts, ",")
	case map[string]any:
		return "[object Object]"
	}
	if f, ok := jsNum(x); ok {
		return jsLenientNumber(f)
	}
	return fmt.Sprint(x)
}

// mcpLower is String.prototype.toLowerCase (full case mapping for U+0130, final sigma by the neighbouring letters).
func mcpLower(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n <= 1 {
			sb.WriteByte(s[i]) // a WTF-8 lone surrogate byte
			i++
			continue
		}
		switch r {
		case 0x130:
			sb.WriteString("i̇")
		case 0x3A3:
			prev, _ := utf8.DecodeLastRuneInString(s[:i])
			next, _ := utf8.DecodeRuneInString(s[i+n:])
			if unicode.IsLetter(prev) && !unicode.IsLetter(next) {
				sb.WriteRune('ς')
			} else {
				sb.WriteRune('σ')
			}
		default:
			sb.WriteRune(unicode.ToLower(r))
		}
		i += n
	}
	return sb.String()
}

// ---- the client half of step-up -----------------------------------------------------------------------------------------

// McpParseChallenges parses a WWW-Authenticate value into [{scheme, params}] (scheme and parameter names lower-cased, quoted
// strings unescaped, a repeated parameter keeps its first value). Tolerant of garbage: a non-string header gives no challenges.
func McpParseChallenges(header any) []any {
	out := []any{}
	h, ok := header.(string)
	if !ok {
		return out
	}
	n := len(h)
	i := 0
	blank := func(c byte) bool { return c == ' ' || c == '\t' }
	ws := func() {
		for i < n && (blank(h[i]) || h[i] == ',') {
			i++
		}
	}
	token := func() string {
		s := i
		for i < n && !strings.ContainsRune(" \t,=\"", rune(h[i])) {
			i++
		}
		return h[s:i]
	}
	var cur map[string]any
	ws()
	for i < n {
		name := token()
		if name == "" {
			i++ // a stray quote or equals sign
			continue
		}
		for i < n && blank(h[i]) {
			i++
		}
		if i < n && h[i] == '=' {
			i++
			for i < n && blank(h[i]) {
				i++
			}
			var val string
			if i < n && h[i] == '"' {
				i++
				var sb strings.Builder
				for i < n && h[i] != '"' {
					if h[i] == '\\' && i+1 < n {
						i++
					}
					sb.WriteByte(h[i])
					i++
				}
				i++ // closing quote
				val = sb.String()
			} else {
				val = token()
			}
			key := mcpLower(name)
			// the reference tests `key in params` on a plain object: these two inherited names are never stored
			if cur != nil && key != "constructor" && key != "__proto__" {
				params := cur["params"].(map[string]any)
				if _, seen := params[key]; !seen {
					params[key] = val
				}
			}
		} else {
			cur = map[string]any{"scheme": mcpLower(name), "params": map[string]any{}}
			out = append(out, cur)
		}
		ws()
	}
	return out
}

// the reference's JS \s
const mcpJSWS = "\\t\\n\\x0b\\x0c\\r \\x{a0}\\x{1680}\\x{2000}-\\x{200a}\\x{2028}\\x{2029}\\x{202f}\\x{205f}\\x{3000}\\x{feff}"

var mcpNeedParam = regexp.MustCompile(`(?:^|[` + mcpJSWS + `,])pca_need="([^"\\]*)"`)

// mcpNeedFromChallenge is pcaNeedFromChallenge: found false when the header has no quoted pca_need; else the decoded need or the
// refusal code.
func mcpNeedFromChallenge(header any) (need map[string]any, code string, found bool) {
	h, ok := header.(string)
	if !ok {
		return nil, "", false
	}
	m := mcpNeedParam.FindStringSubmatch(h)
	if m == nil {
		return nil, "", false
	}
	v := m[1]
	if v == "" {
		return nil, "bad_base64", true
	}
	if jsLen(v) > a2aNeedMaxEncoded {
		return nil, "too_long", true
	}
	raw, ok := DecodeB64uStrict(v, -1)
	if !ok {
		return nil, "bad_base64", true
	}
	raw = []byte(strings.TrimPrefix(string(raw), "\xef\xbb\xbf")) // TextDecoder drops a leading BOM
	if !utf8.Valid(raw) {
		return nil, "bad_utf8", true
	}
	parsed, err := StrictParse(string(raw))
	if err != nil {
		return nil, "bad_json", true
	}
	if c := ValidateA2ANeed(parsed); c != "" {
		return nil, c, true
	}
	return parsed.(map[string]any), "", true
}

// McpPcaNeedProblem is the reason a present-but-unusable pca_need was ignored ("" when absent or usable).
func McpPcaNeedProblem(header any) string {
	_, code, _ := mcpNeedFromChallenge(header)
	return code
}

func mcpSplitScopes(x any) []string {
	s, ok := x.(string)
	if !ok {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, " ") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// McpPlanStepUp decides the next step for a response. Only 403 with error="insufficient_scope" on a Bearer challenge is a
// step-up. state = {requested, attempts, maxAttempts?, pcaAware?}. The scope list is the union of what was requested and what
// the challenge names, sorted; an unchanged union without a usable pca_need gives up instead of looping. It approves nothing.
func McpPlanStepUp(status, wwwAuthenticate, state any) (map[string]any, error) {
	st, ok := state.(map[string]any)
	if !ok {
		return nil, errors.New("planStepUp: state must be an object")
	}
	giveUp := func(reason string) map[string]any { return map[string]any{"action": "give_up", "reason": reason} }
	max := 3.0
	if v := st["maxAttempts"]; v != nil {
		f, ok := jsNum(v)
		if !ok {
			return nil, errors.New("planStepUp: maxAttempts must be a number")
		}
		max = f
	}
	var bearer map[string]any
	if jsStrictEq(status, 403) {
		for _, c := range McpParseChallenges(wwwAuthenticate) {
			if cm := c.(map[string]any); cm["scheme"] == "bearer" {
				bearer = cm
				break
			}
		}
	}
	if bearer == nil || bearer["params"].(map[string]any)["error"] != "insufficient_scope" {
		return giveUp("not_insufficient_scope"), nil
	}
	attempts, ok := jsNum(st["attempts"])
	if !ok {
		return nil, errors.New("planStepUp: attempts must be a number")
	}
	if !(finite(attempts) && attempts < max) { // a non-finite count gives up; an infinite limit is the unbounded one
		return giveUp("retry_limit"), nil
	}
	req, err := mcpIter(st["requested"])
	if err != nil {
		return nil, fmt.Errorf("planStepUp: requested: %w", err)
	}
	had := map[string]bool{}
	union := []string{}
	for _, r := range req {
		s, ok := r.(string)
		if !ok {
			return nil, errors.New("planStepUp: requested scopes must be strings")
		}
		if !had[s] {
			had[s] = true
			union = append(union, s)
		}
	}
	inUnion := map[string]bool{}
	for _, s := range union {
		inUnion[s] = true
	}
	for _, s := range mcpSplitScopes(bearer["params"].(map[string]any)["scope"]) {
		if !inUnion[s] {
			inUnion[s] = true
			union = append(union, s)
		}
	}
	sort.SliceStable(union, func(a, b int) bool { return compareUnits(utf16Units(union[a]), utf16Units(union[b])) < 0 })
	scopes := make([]any, len(union))
	for i, s := range union {
		scopes[i] = s
	}
	next := jsNumber(attempts + 1)
	if aware, _ := st["pcaAware"].(bool); aware {
		if need, _, found := mcpNeedFromChallenge(wwwAuthenticate); found && need != nil {
			return map[string]any{"action": "pca", "need": need, "fallbackScopes": scopes, "attempts": next}, nil
		}
		// a missing or malformed pca_need is not an error: fall through to the stock behaviour
	}
	fresh := false
	for _, s := range union {
		if !had[s] {
			fresh = true
		}
	}
	if !fresh {
		return giveUp("no_new_scope"), nil
	}
	return map[string]any{"action": "scope", "scopes": scopes, "attempts": next}, nil
}

// McpCheckAuthorizationResponseIss is RFC 9207 section 2.4 as tabulated in the MCP authorization specification: a present iss is
// compared with the recorded issuer by plain string comparison (no normalization); an absent iss is refused only when the server
// advertised authorization_response_iss_parameter_supported; without a recorded issuer nothing can be checked and the response is
// refused. a = {recordedIssuer, issParameterSupported, iss}; an absent iss differs from a null one.
func McpCheckAuthorizationResponseIss(a any) (map[string]any, error) {
	m, ok := a.(map[string]any)
	if !ok {
		return nil, errors.New("checkAuthorizationResponseIss: argument must be an object")
	}
	no := func(reason string) map[string]any { return map[string]any{"proceed": false, "reason": reason} }
	rec, ok := m["recordedIssuer"].(string)
	if !ok || rec == "" {
		return no("no_recorded_issuer"), nil
	}
	iss, has := m["iss"]
	if !has {
		if m["issParameterSupported"] == true {
			return no("iss_missing"), nil
		}
		return map[string]any{"proceed": true}, nil
	}
	if s, ok := iss.(string); ok && s == rec {
		return map[string]any{"proceed": true}, nil
	}
	return no("iss_mismatch"), nil
}

// ---- tool result meta / headers -----------------------------------------------------------------------------------------

// McpGuardToolResult attaches the encoded PCActn (pca.encoded) into a tool result's _meta under "x-pca-action", keeping the
// result's members and its existing _meta members. A null pca or result is refused (the reference throws).
func McpGuardToolResult(pca, result any) (map[string]any, error) {
	if result == nil {
		return nil, errors.New("guardToolResult: result must not be null")
	}
	if pca == nil {
		return nil, errors.New("guardToolResult: pca must not be null")
	}
	meta := map[string]any{}
	switch t := mcpGet(result, "_meta").(type) {
	case map[string]any, []any:
		meta = mcpSpread(t)
	}
	if enc := mcpGet(pca, "encoded"); mcpIsUnd(enc) {
		delete(meta, "x-pca-action")
	} else {
		meta["x-pca-action"] = enc
	}
	out := mcpSpread(result)
	out["_meta"] = meta
	return out, nil
}

// McpPcaHeaders is the PCA-Action header: base64url of the UTF-8 text of the encoded PCActn.
func McpPcaHeaders(encoded string) map[string]string {
	return map[string]string{PCAHeader: b64.EncodeToString([]byte(wellFormedUTF8(encoded)))}
}

// ---- MCP tools -> the site's action schema ------------------------------------------------------------------------------

const (
	mcpMaxRefDepth = 8
	mcpMaxRefNodes = 20000
)

type mcpCtx struct {
	root any
	todo []any
	left int
}

func (c *mcpCtx) note(format string, a ...any) { c.todo = append(c.todo, fmt.Sprintf(format, a...)) }

// mcpPointer follows a local `#/a/b` JSON pointer; ok is false when absent, not local, or not an object.
func mcpPointer(root any, ref string) (any, bool) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, false
	}
	cur := root
	for _, raw := range strings.Split(ref[2:], "/") {
		seg := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch t := cur.(type) {
		case map[string]any:
			v, has := t[seg]
			if !has {
				return nil, false
			}
			cur = v
		case []any:
			n, ok := canonDec(seg)
			if !ok || n >= len(t) {
				return nil, false
			}
			cur = t[n]
		default:
			return nil, false
		}
	}
	switch cur.(type) {
	case map[string]any, []any:
		return cur, true
	}
	return nil, false
}

func mcpIsNullType(m map[string]any) bool {
	switch t := m["type"].(type) {
	case string:
		return t == "null"
	case []any:
		for _, x := range t {
			if x != "null" {
				return false
			}
		}
		return true
	}
	return false
}

func mcpEnumStrings(x any) ([]any, bool) {
	l, ok := x.([]any)
	if !ok {
		return nil, false
	}
	for _, e := range l {
		if _, ok := e.(string); !ok {
			return nil, false
		}
	}
	return l, true
}

// mcpFlatten follows local $refs, merges allOf and collapses anyOf / oneOf to its single non-null variant (or the union of string
// constants). What cannot be represented is noted in todo and left empty (the caller declares it a string: the draft fails closed).
func mcpFlatten(s any, c *mcpCtx, where string, depth int) (map[string]any, error) {
	var cur map[string]any
	switch t := s.(type) {
	case map[string]any:
		cur = t
	case []any:
		cur = map[string]any{} // a bare array has no schema members
	default:
		return map[string]any{}, nil
	}
	c.left--
	if c.left < 0 {
		if c.left == -1 {
			c.note("%s: schema expansion stopped after %d nodes (declared string; refine or drop)", where, mcpMaxRefNodes)
		}
		return map[string]any{}, nil
	}
	if depth > mcpMaxRefDepth {
		c.note("%s: schema nesting or reference chain deeper than %d (declared string; refine or drop)", where, mcpMaxRefDepth)
		return map[string]any{}, nil
	}
	if ref, ok := cur["$ref"].(string); ok {
		target, found := mcpPointer(c.root, ref)
		if !found {
			c.note("%s: reference '%s' is not a local reference that resolves (declared string; refine or drop)", where, mcpSliceUnits(ref, 120))
			return map[string]any{}, nil
		}
		inner, err := mcpFlatten(target, c, where, depth+1)
		if err != nil {
			return nil, err
		}
		merged := mcpCopy(inner)
		for k, v := range cur {
			if k != "$ref" {
				merged[k] = v
			}
		}
		cur = merged
	}
	if all, ok := cur["allOf"].([]any); ok {
		rest := mcpCopy(cur)
		delete(rest, "allOf")
		flat := make([]map[string]any, len(all))
		for i, x := range all {
			m, err := mcpFlatten(x, c, where, depth+1)
			if err != nil {
				return nil, err
			}
			flat[i] = m
		}
		acc := map[string]any{}
		for _, m := range flat {
			nxt := mcpCopy(acc)
			for k, v := range m {
				nxt[k] = v
			}
			props := mcpSpread(acc["properties"])
			for k, v := range mcpSpread(m["properties"]) {
				props[k] = v
			}
			nxt["properties"] = props
			reqs := []any{}
			for _, r := range []any{acc["required"], m["required"]} {
				if r == nil {
					continue
				}
				l, err := mcpIter(r)
				if err != nil {
					return nil, fmt.Errorf("%s: required: %w", where, err)
				}
				reqs = append(reqs, l...)
			}
			nxt["required"] = reqs
			acc = nxt
		}
		for k, v := range rest {
			acc[k] = v
		}
		cur = acc
	}
	alts := cur["anyOf"]
	if alts == nil {
		alts = cur["oneOf"]
	}
	if list, ok := alts.([]any); ok {
		rest := mcpCopy(cur)
		delete(rest, "anyOf")
		delete(rest, "oneOf")
		live := []map[string]any{}
		for _, x := range list {
			m, err := mcpFlatten(x, c, where, depth+1)
			if err != nil {
				return nil, err
			}
			if !mcpIsNullType(m) {
				live = append(live, m)
			}
		}
		if len(live) == 1 {
			out := mcpCopy(live[0])
			for k, v := range rest {
				out[k] = v
			}
			return out, nil
		}
		consts := []any{}
		all := len(live) > 1
		seen := map[string]bool{}
		for _, m := range live {
			if k, ok := m["const"].(string); ok {
				if !seen[k] {
					seen[k] = true
					consts = append(consts, k)
				}
			} else if e, ok := mcpEnumStrings(m["enum"]); ok {
				for _, x := range e {
					if k := x.(string); !seen[k] {
						seen[k] = true
						consts = append(consts, k)
					}
				}
			} else {
				all = false
			}
		}
		if all {
			out := mcpCopy(rest)
			out["type"] = "string"
			out["enum"] = consts
			return out, nil
		}
		c.note("%s: a union of %d schemas has no schema representation (declared string; refine or drop)", where, len(live))
		return rest, nil
	}
	if k, ok := cur["const"].(string); ok {
		if _, has := cur["enum"]; !has {
			cur = mcpCopy(cur)
			cur["enum"] = []any{k}
		}
	}
	return cur, nil
}

func mcpSlice1024(x any) (any, error) {
	switch t := x.(type) {
	case string:
		return mcpSliceUnits(t, 1024), nil
	case []any:
		if len(t) > 1024 {
			return t[:1024], nil
		}
		return t, nil
	}
	return nil, errors.New("description.slice is not a function")
}

// mcpDecl is the JSON Schema property -> parameter declaration. Sensitivity defaults to material; shapes the schema cannot carry
// (objects, fractions) become string placeholders noted in todo so the developer must decide.
func mcpDecl(name string, schema any, required bool, c *mcpCtx) (map[string]any, error) {
	s, err := mcpFlatten(schema, c, "action.params."+name, 0)
	if err != nil {
		return nil, err
	}
	t := mcpGet(s, "type")
	if l, ok := t.([]any); ok {
		t = mcpUnd
		for _, x := range l {
			if x != "null" {
				t = x
				break
			}
		}
	}
	base := map[string]any{"semantic": "unknown", "sensitivity": "material"}
	if v := s["x-pca-semantic"]; v != nil {
		base["semantic"] = v
	}
	if v := s["x-pca-sensitivity"]; v != nil {
		base["sensitivity"] = v
	}
	if !required {
		base["required"] = false
	}
	if d := s["description"]; mcpTruthy(d) {
		sl, err := mcpSlice1024(d)
		if err != nil {
			return nil, err
		}
		base["description"] = sl
	}
	if !mcpTruthy(s["x-pca-semantic"]) {
		c.note("action.params.%s: semantic type", name)
	}
	with := func(typ string, extra map[string]any) map[string]any {
		out := mcpCopy(base)
		out["type"] = typ
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	switch t {
	case "integer":
		x := map[string]any{}
		if _, ok := mcpSafeInt(s["minimum"]); ok {
			x["min"] = s["minimum"]
		} else if f, ok := mcpSafeInt(s["exclusiveMinimum"]); ok {
			x["min"] = jsNumber(f + 1)
		}
		if _, ok := mcpSafeInt(s["maximum"]); ok {
			x["max"] = s["maximum"]
		} else if f, ok := mcpSafeInt(s["exclusiveMaximum"]); ok {
			x["max"] = jsNumber(f - 1)
		}
		if mcpTruthy(s["x-pca-unit"]) {
			x["unit"] = s["x-pca-unit"]
		}
		if mcpTruthy(s["x-pca-accumulates-into"]) {
			x["accumulates_into"] = s["x-pca-accumulates-into"]
		}
		return with("integer", x), nil
	case "boolean":
		return with("boolean", nil), nil
	case "string":
		if s["format"] == "date" {
			return with("date", nil), nil
		}
		x := map[string]any{}
		if e, ok := mcpEnumStrings(s["enum"]); ok {
			x["values"] = e
		}
		if f, ok := mcpSafeInt(s["maxLength"]); ok && f > 0 {
			x["max_len"] = s["maxLength"]
		}
		return with("string", x), nil
	case "array":
		it, err := mcpFlatten(s["items"], c, fmt.Sprintf("action.params.%s[]", name), 0)
		if err != nil {
			return nil, err
		}
		x := map[string]any{}
		if e, ok := mcpEnumStrings(it["enum"]); ok && mcpTruthy(s["uniqueItems"]) {
			x["values"] = e
			if _, ok := mcpSafeInt(s["minItems"]); ok {
				x["min_items"] = s["minItems"]
			}
			if _, ok := mcpSafeInt(s["maxItems"]); ok {
				x["max_items"] = s["maxItems"]
			}
			return with("set", x), nil
		}
		itT := it["type"]
		if l, ok := itT.([]any); ok {
			itT = nil
			if len(l) > 0 {
				itT = l[0]
			}
		}
		if itT == "integer" {
			x["items"] = "integer"
		}
		if _, ok := mcpSafeInt(s["maxItems"]); ok {
			x["max_items"] = s["maxItems"]
		}
		if _, ok := mcpSafeInt(s["minItems"]); ok {
			x["min_items"] = s["minItems"]
		}
		return with("array", x), nil
	}
	c.note("action.params.%s: type '%s' has no schema representation (declared string; refine or drop)", name, mcpJSStr(t))
	return with("string", nil), nil
}

func mcpNameOK(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// McpDraftActionSchema drafts the site's action schema from an MCP tools/list (tools: a JSON array). Verb = verbPrefix + tool
// name; every write verb is drafted irreversible (the fail-closed default; a destructive hint only keeps it at least
// rate_limited, a read-only hint reads). site = {site, aud, version, verbPrefix?}. Returns {schema, todo}: the decisions the
// developer must make before signing.
func McpDraftActionSchema(tools, site any) (map[string]any, error) {
	list, ok := tools.([]any)
	if !ok {
		return nil, errors.New("draftActionSchemaFromMcp: tools must be an array")
	}
	sm, ok := site.(map[string]any)
	if !ok {
		return nil, errors.New("draftActionSchemaFromMcp: site must be an object")
	}
	var todo []any
	verbs := []map[string]any{}
	for _, t := range list {
		if t == nil {
			return nil, errors.New("draftActionSchemaFromMcp: a tool must not be null")
		}
		c := &mcpCtx{left: mcpMaxRefNodes, todo: todo}
		if in := mcpGet(t, "inputSchema"); !mcpIsUnd(in) {
			c.root = in
		}
		nameV := mcpGet(t, "name")
		name := mcpJSStr(nameV)
		input, err := mcpFlatten(mcpGet(t, "inputSchema"), c, name+": inputSchema", 0)
		if err != nil {
			return nil, err
		}
		props := input["properties"]
		req := map[string]bool{}
		if r := input["required"]; r != nil {
			l, err := mcpIter(r)
			if err != nil {
				return nil, fmt.Errorf("%s: required: %w", name, err)
			}
			for _, x := range l {
				if s, ok := x.(string); ok {
					req[s] = true
				}
			}
		}
		params := map[string]any{}
		for _, pn := range mcpKeys(props) {
			if !mcpNameOK(pn) {
				c.note("%s: parameter '%s' is not a schema name ([A-Za-z0-9_]{1,64}); rename it", name, pn)
				continue
			}
			d, err := mcpDecl(pn, mcpIndex(props, pn), req[pn], c)
			if err != nil {
				return nil, err
			}
			params["action.params."+pn] = d
		}
		kind := "write"
		if a := mcpGet(t, "annotations"); mcpGet(a, "readOnlyHint") == true {
			kind = "read"
		}
		prefix := ""
		if p := sm["verbPrefix"]; p != nil {
			prefix = mcpJSStr(p)
		}
		verb := prefix + name
		rev := "reversible"
		if kind == "write" {
			c.note("%s: reversibility (drafted irreversible)", verb)
			rev = "irreversible"
		}
		todo = c.todo
		entry := map[string]any{"verb": verb, "kind": kind, "params": params, "reversibility": rev, "mcp": map[string]any{}}
		if !mcpIsUnd(nameV) {
			entry["mcp"] = map[string]any{"tool": nameV}
		}
		if d := mcpGet(t, "description"); mcpTruthy(d) {
			sl, err := mcpSlice1024(d)
			if err != nil {
				return nil, err
			}
			entry["description"] = sl
		}
		verbs = append(verbs, entry)
	}
	sort.SliceStable(verbs, func(a, b int) bool { return compareUtf8(verbs[a]["verb"].(string), verbs[b]["verb"].(string)) < 0 })
	vl := make([]any, len(verbs))
	for i, v := range verbs {
		vl[i] = v
	}
	schema := map[string]any{"v": 1, "kind": actionSchemaKind, "verbs": vl}
	for _, k := range []string{"site", "aud", "version"} {
		if v, has := sm[k]; has {
			schema[k] = v
		}
	}
	if todo == nil {
		todo = []any{}
	}
	return map[string]any{"schema": schema, "todo": todo}, nil
}

// mcpClone is JSON.parse(JSON.stringify(v)): a deep copy in which -0 becomes 0.
func mcpClone(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = mcpClone(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = mcpClone(x)
		}
		return out
	}
	if f, ok := jsNum(v); ok && f == 0 {
		return jsNumber(0)
	}
	return v
}

// McpApplySchemaDecisions records the developer's decisions on a draft (a new object). d = {verbs: {<verb>: {reversibility?,
// params?: {<path>: members}}}, units?}. A decision about a verb or parameter the draft does not have is an error: the schema is
// closed, so a typo must not silently publish a looser schema.
func McpApplySchemaDecisions(draft, d any) (map[string]any, error) {
	out, ok := mcpClone(draft).(map[string]any)
	if !ok {
		return nil, errors.New("applySchemaDecisions: the draft must be an object")
	}
	dm, ok := d.(map[string]any)
	if !ok {
		return nil, errors.New("applySchemaDecisions: decisions must be an object")
	}
	if u := dm["units"]; mcpTruthy(u) {
		merged := mcpSpread(out["units"])
		for k, v := range mcpSpread(u) {
			merged[k] = v
		}
		out["units"] = merged
	}
	dv := dm["verbs"]
	if mcpNullish(dv) {
		return nil, errors.New("applySchemaDecisions: decisions.verbs must be an object")
	}
	for _, verb := range mcpKeys(dv) {
		decision := mcpIndex(dv, verb)
		vs, ok := out["verbs"].([]any)
		if !ok {
			return nil, errors.New("applySchemaDecisions: the draft has no verbs list")
		}
		var v map[string]any
		for _, x := range vs {
			if x == nil {
				return nil, errors.New("applySchemaDecisions: a verb entry must not be null")
			}
			if m, ok := x.(map[string]any); ok && m["verb"] == verb {
				v = m
				break
			}
		}
		if v == nil {
			return nil, fmt.Errorf("applySchemaDecisions: the draft has no verb '%s'", verb)
		}
		if decision == nil {
			return nil, errors.New("applySchemaDecisions: a decision must not be null")
		}
		if r := mcpGet(decision, "reversibility"); mcpTruthy(r) {
			v["reversibility"] = r
		}
		dps := mcpGet(decision, "params")
		if mcpNullish(dps) {
			continue
		}
		for _, path := range mcpKeys(dps) {
			if mcpNullish(v["params"]) {
				return nil, errors.New("applySchemaDecisions: the verb has no params")
			}
			p := mcpGet(v["params"], path)
			if !mcpTruthy(p) {
				return nil, fmt.Errorf("applySchemaDecisions: verb '%s' has no parameter '%s'", verb, path)
			}
			if pm, ok := p.(map[string]any); ok { // Object.assign onto a non-object changes nothing observable
				for k, x := range mcpSpread(mcpIndex(dps, path)) {
					pm[k] = x
				}
			}
		}
	}
	return out, nil
}

// McpVerbOfTool is the schema verb an MCP tool maps to (by mcp.tool): nil when none. A schema without a verbs array is an error.
func McpVerbOfTool(schema any, tool string) (any, error) {
	m, ok := schema.(map[string]any)
	if !ok {
		return nil, errors.New("verbOfTool: the schema must be an object")
	}
	verbs, ok := m["verbs"].([]any)
	if !ok {
		return nil, errors.New("verbOfTool: schema.verbs is not an array")
	}
	for _, x := range verbs {
		if x == nil {
			return nil, errors.New("verbOfTool: a verb entry must not be null")
		}
		if t, ok := mcpGet(mcpGet(x, "mcp"), "tool").(string); ok && t == tool {
			if v := mcpGet(x, "verb"); !mcpIsUnd(v) {
				return v, nil
			}
			return nil, nil
		}
	}
	return nil, nil
}

// McpConformToolCall maps a tool call to the schema's verb and runs the closed-world check (an unmapped tool is an unknown verb):
// {ok:true, verb} or {ok:false, code, path?, reason}.
func McpConformToolCall(schema any, tool string, args any) (map[string]any, error) {
	v, err := McpVerbOfTool(schema, tool)
	if err != nil {
		return nil, err
	}
	verb, isStr := v.(string)
	if !isStr {
		return map[string]any{"ok": false, "code": "unknown_verb", "reason": "MCP tool '" + tool + "' is not declared by the site schema"}, nil
	}
	res, reason := conformActionReason(schema, verb, args)
	if !res.OK {
		out := map[string]any{"ok": false, "code": res.Code, "reason": reason}
		if res.Path != "" {
			out["path"] = res.Path
		}
		return out, nil
	}
	decl, _ := schemaVerbOf(schema, verb)
	return map[string]any{"ok": true, "verb": decl}, nil
}
