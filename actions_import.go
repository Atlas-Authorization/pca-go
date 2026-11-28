package pca

// Action importers, shared core: the input bounds, the import context, text hygiene, verb naming, the bounded `$ref` resolver,
// the JSON Schema to ParamDef flattening and the single place a draft ActionDef is assembled (always `unreviewed`). Sources are
// parsed JSON values (map[string]any / []any / string / json.Number / bool / nil, as ParseJSONLenient yields them); an importer
// returns an ActionImportReport. Options are a JSON object: ns, uri, licence, now, limits, allowExtensions (and, for a JSON
// Schema import, verb, title, description, effects). The reference's JavaScript semantics (UTF-16 lengths, lone surrogates,
// object spread of any value, property reads on any value) are reproduced where an output depends on them.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// ---- results ------------------------------------------------------------------------------------------------------------

// ActionImportKinds are the import source kinds.
var ActionImportKinds = []string{"openapi", "mcp", "graphql", "grpc", "asyncapi", "jsonschema"}

// ActionImportTodo is a decision the importer could not make for the developer, or a fact worth a reviewer's eye. Never silent.
type ActionImportTodo struct {
	Where   string `json:"where"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ActionImportSource records where the defs came from (spec_digest: base64url sha256 of the text bytes or of the lenient canonical form).
type ActionImportSource struct {
	Kind       string      `json:"kind"`
	URI        string      `json:"uri"`
	SpecDigest string      `json:"spec_digest"`
	Licence    string      `json:"licence"`
	ImportedAt json.Number `json:"imported_at"`
}

// ActionImportReport is what an importer returns: the unreviewed defs, the notes and the source record.
type ActionImportReport struct {
	Defs   []map[string]any   `json:"defs"`
	Todo   []ActionImportTodo `json:"todo"`
	Source ActionImportSource `json:"source"`
}

func (s ActionImportSource) asMap() map[string]any {
	return map[string]any{"kind": s.Kind, "uri": s.URI, "spec_digest": s.SpecDigest, "licence": s.Licence, "imported_at": s.ImportedAt}
}

// ---- thrown errors -------------------------------------------------------------------------------------------------------
// The reference throws from deep inside the walkers; the port panics with an aimThrow and each public entry point recovers it.

type aimThrow struct{ err error }

func aimFail(code, msg string) { panic(aimThrow{&CodedError{Code: code, Msg: msg}}) }

func aimRecover(err *error) {
	if r := recover(); r != nil {
		if t, ok := r.(aimThrow); ok {
			*err = t.err
			return
		}
		panic(r)
	}
}

// ---- limits -------------------------------------------------------------------------------------------------------------

type actionImportLimits struct {
	maxBytes, maxOps, maxJSONDepth, maxNodes, maxRefNodes, maxRefDepth int64
}

var (
	aimDefaultLimits = actionImportLimits{64 * 1024 * 1024, 20_000, 64, 6_000_000, 20_000, 8}
	aimHardLimits    = actionImportLimits{256 * 1024 * 1024, 50_000, 128, 20_000_000, 200_000, 16}
)

func (l actionImportLimits) asMap() map[string]any {
	n := func(v int64) any { return json.Number(strconv.FormatInt(v, 10)) }
	return map[string]any{"max_bytes": n(l.maxBytes), "max_ops": n(l.maxOps), "max_json_depth": n(l.maxJSONDepth), "max_nodes": n(l.maxNodes), "max_ref_nodes": n(l.maxRefNodes), "max_ref_depth": n(l.maxRefDepth)}
}

// aimResolveLimits applies the caller's limits over the defaults, each clamped to the hard ceiling. Only an object carries limits.
func aimResolveLimits(over any) actionImportLimits {
	out := aimDefaultLimits
	m, _ := over.(map[string]any)
	slots := []struct {
		k    string
		dst  *int64
		hard int64
	}{
		{"max_bytes", &out.maxBytes, aimHardLimits.maxBytes}, {"max_ops", &out.maxOps, aimHardLimits.maxOps},
		{"max_json_depth", &out.maxJSONDepth, aimHardLimits.maxJSONDepth}, {"max_nodes", &out.maxNodes, aimHardLimits.maxNodes},
		{"max_ref_nodes", &out.maxRefNodes, aimHardLimits.maxRefNodes}, {"max_ref_depth", &out.maxRefDepth, aimHardLimits.maxRefDepth},
	}
	for _, s := range slots {
		v, has := m[s.k]
		if !has {
			continue
		}
		f, _ := jsNum(v)
		if !jsIsSafeInteger(v) || f < 1 {
			aimFail("bad_limit", "limit "+s.k+" must be a positive safe integer")
		}
		*s.dst = int64(math.Min(f, float64(s.hard)))
	}
	return out
}

// aimTextSizeCheck is the size check of a text source (UTF-8 bytes).
func aimTextSizeCheck(text any, lim actionImportLimits) {
	s, ok := text.(string)
	if !ok {
		aimFail("bad_source", "the source must be text")
	}
	if int64(jsLen(s))*3 > lim.maxBytes && int64(utf8Len(s)) > lim.maxBytes {
		aimFail("import_limit", fmt.Sprintf("the source is larger than %d bytes", lim.maxBytes))
	}
}

// aimCheckParsed walks a parsed source iteratively and refuses it when it is not plain JSON data or is deeper or larger than the
// limits. Returns the node count.
func aimCheckParsed(root any, lim actionImportLimits) int64 {
	type frame struct {
		v any
		d int64
	}
	var nodes, size int64
	stack := []frame{{root, 0}}
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		nodes++
		if nodes > lim.maxNodes {
			aimFail("import_limit", fmt.Sprintf("the source has more than %d nodes", lim.maxNodes))
		}
		if f.d > lim.maxJSONDepth {
			aimFail("import_limit", fmt.Sprintf("the source nests deeper than %d", lim.maxJSONDepth))
		}
		switch t := f.v.(type) {
		case nil, bool:
			size += 4
		case string:
			size += int64(jsLen(t))
		case []any:
			size += 2 + int64(len(t))
			for _, x := range t {
				stack = append(stack, frame{x, f.d + 1})
			}
		case map[string]any:
			for _, k := range jsKeys(t) {
				size += int64(jsLen(k)) + 4
				stack = append(stack, frame{t[k], f.d + 1})
			}
		default:
			n, ok := jsNum(f.v)
			if !ok {
				aimFail("bad_source", fmt.Sprintf("the source holds a %T", f.v))
			}
			if math.IsNaN(n) || math.IsInf(n, 0) {
				aimFail("bad_source", "the source holds a non-finite number")
			}
			size += 8
		}
		if size > lim.maxBytes {
			aimFail("import_limit", fmt.Sprintf("the source is larger than %d bytes", lim.maxBytes))
		}
	}
	return nodes
}

// ---- context ------------------------------------------------------------------------------------------------------------

var aimDefaultExtensions = []string{"x-pca-verb", "x-pca-role", "x-pca-internal"}

var reAimNS = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

type aimCtx struct {
	ns, kind string
	lim      actionImportLimits
	todo     []ActionImportTodo
	source   ActionImportSource
	ext      map[string]bool
	root     any // parsed-source root that `#/...` references resolve in
	verbs    map[string]bool
	aliases  map[string]string
	defs     []map[string]any
}

func aimOpt(opts any, k string) any {
	m, _ := opts.(map[string]any)
	return m[k]
}

func aimNewCtx(kind string, source any, opts any) *aimCtx {
	ns, isStr := aimOpt(opts, "ns").(string)
	if !isStr || !reAimNS.MatchString(ns) {
		aimFail("bad_ns", "ns must match [a-z][a-z0-9_]{0,31}")
	}
	lim := aimResolveLimits(aimOpt(opts, "limits"))
	var digest string
	switch t := source.(type) {
	case string:
		aimTextSizeCheck(t, lim)
		h := sha256.Sum256([]byte(wellFormedUTF8(t)))
		digest = base64.RawURLEncoding.EncodeToString(h[:])
	case []byte:
		if int64(len(t)) > lim.maxBytes {
			aimFail("import_limit", fmt.Sprintf("the source is larger than %d bytes", lim.maxBytes))
		}
		h := sha256.Sum256(t)
		digest = base64.RawURLEncoding.EncodeToString(h[:])
	default:
		aimCheckParsed(source, lim)
		canon, _ := canonicalLenient(source)
		h := sha256.Sum256([]byte(wellFormedUTF8(canon)))
		digest = base64.RawURLEncoding.EncodeToString(h[:])
	}
	now := json.Number("0")
	if v := aimOpt(opts, "now"); v != nil {
		f, _ := jsNum(v)
		if !jsIsSafeInteger(v) || f < 0 {
			aimFail("bad_opts", "now must be a non-negative integer")
		}
		now = json.Number(strconv.FormatInt(int64(f), 10))
	}
	uri, licence := aimOpt(opts, "uri"), aimOpt(opts, "licence")
	if uri == nil {
		uri = "source:" + kind
	}
	if licence == nil {
		licence = "unknown"
	}
	ext := map[string]bool{}
	switch e := aimOpt(opts, "allowExtensions").(type) {
	case nil:
		for _, k := range aimDefaultExtensions {
			ext[k] = true
		}
	case []any:
		for _, x := range e {
			if s, ok := x.(string); ok {
				ext[s] = true
			}
		}
	case string:
		for _, r := range e {
			ext[string(r)] = true
		}
	default:
		aimFail("type_error", "allowExtensions is not iterable")
	}
	return &aimCtx{ns: ns, kind: kind, lim: lim, ext: ext, root: source, verbs: map[string]bool{}, aliases: map[string]string{},
		source: ActionImportSource{Kind: kind, URI: aimClip(uri, 2048), SpecDigest: digest, Licence: aimClip(licence, 128), ImportedAt: now}}
}

func aimAddTodo(c *aimCtx, where, code, message string) {
	// a hostile spec could make millions of todos: keep the first 5,000 and one sentinel
	switch n := len(c.todo); {
	case n < 5000:
		c.todo = append(c.todo, ActionImportTodo{aimClip(where, 200), code, aimClip(message, 400)})
	case n == 5000:
		c.todo = append(c.todo, ActionImportTodo{"*", "todo_truncated", "further notes omitted"})
	}
}

func aimFinish(c *aimCtx) *ActionImportReport {
	defs := c.defs
	if defs == nil {
		defs = []map[string]any{}
	}
	todo := c.todo
	if todo == nil {
		todo = []ActionImportTodo{}
	}
	return &ActionImportReport{Defs: defs, Todo: todo, Source: c.source}
}

// ---- JSON value helpers --------------------------------------------------------------------------------------------------

func aimObj(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }

// aimGet is o[k] of a JSON value: an own member of an object, else undefined (an array or scalar has no such member here).
func aimGet(o any, k string) (any, bool) {
	m, ok := o.(map[string]any)
	if !ok {
		return nil, false
	}
	v, has := m[k]
	return v, has
}

func aimStrOf(o any, k string) (string, bool) {
	v, _ := aimGet(o, k)
	s, ok := v.(string)
	return s, ok
}

func aimIsTrue(v any) bool { b, ok := v.(bool); return ok && b }

func aimStrEq(v any, s string) bool { x, ok := v.(string); return ok && x == s }

// aimSpreadObj is {...v}: an object's members, an array's / string's indexed members, nothing for a scalar.
func aimSpreadObj(v any) map[string]any {
	out := map[string]any{}
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			out[k] = x
		}
	case []any:
		for i, x := range t {
			out[strconv.Itoa(i)] = x
		}
	case string:
		for i, u := range utf16Units(t) {
			out[strconv.Itoa(i)] = string(utf16.Decode([]uint16{u}))
		}
	}
	return out
}

// aimSpreadArr is [...v]: an array or a string (by code point); anything else is not iterable.
func aimSpreadArr(v any) []any {
	switch t := v.(type) {
	case []any:
		return append([]any(nil), t...)
	case string:
		var out []any
		for _, r := range t {
			out = append(out, string(r))
		}
		return out
	}
	aimFail("type_error", "value is not iterable")
	return nil
}

func aimSortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return compareUtf8(ks[i], ks[j]) < 0 })
	return ks
}

// aimDecodeURIComponent is decodeURIComponent, or the raw segment when the escape is malformed.
func aimDecodeURIComponent(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var sb strings.Builder
	var run []byte
	flush := func() bool {
		if len(run) == 0 {
			return true
		}
		ok := utf8.Valid(run)
		sb.Write(run)
		run = run[:0]
		return ok
	}
	for i := 0; i < len(s); {
		if s[i] != '%' {
			if !flush() {
				return s
			}
			sb.WriteByte(s[i])
			i++
			continue
		}
		if i+3 > len(s) {
			return s
		}
		h, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return s
		}
		run = append(run, byte(h))
		i += 3
	}
	if !flush() {
		return s
	}
	return sb.String()
}

// aimPointer follows a local `#/a/b` JSON pointer in root; nil (and false) when absent, not local, or not an object or array.
func aimPointer(root any, ref any) (any, bool) {
	r, ok := ref.(string)
	if !ok || !strings.HasPrefix(r, "#/") {
		return nil, false
	}
	cur := root
	for _, raw := range strings.Split(r[2:], "/") {
		seg := aimDecodeURIComponent(strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~"))
		switch t := cur.(type) {
		case map[string]any:
			v, has := t[seg]
			if !has {
				return nil, false
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(t) || strconv.Itoa(i) != seg {
				return nil, false // `length` is an own member of an array but never an object
			}
			cur = t[i]
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

// ---- text hygiene --------------------------------------------------------------------------------------------------------

func aimIsCtrl(r rune) bool {
	return (r >= 0 && r <= 8) || r == 0x0B || r == 0x0C || (r >= 0x0E && r <= 0x1F) || (r >= 0x7F && r <= 0x9F) || r == 0x2028 || r == 0x2029 ||
		(r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

// aimStripLone removes the lone surrogates of a (WTF-8) string.
func aimStripLone(s string) string {
	if !hasLoneSurrogate(s) {
		return s
	}
	u := utf16Units(s)
	out := make([]uint16, 0, len(u))
	for i := 0; i < len(u); i++ {
		switch {
		case u[i] >= 0xD800 && u[i] <= 0xDBFF && i+1 < len(u) && u[i+1] >= 0xDC00 && u[i+1] <= 0xDFFF:
			out = append(out, u[i], u[i+1])
			i++
		case u[i] >= 0xD800 && u[i] <= 0xDFFF:
		default:
			out = append(out, u[i])
		}
	}
	return string(utf16.Decode(out))
}

// aimClip is NFC, no lone surrogates, no control or bidi-override characters, whitespace collapsed, cut to maxBytes at a code point.
func aimClip(v any, maxBytes int) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	t := strings.Map(func(r rune) rune {
		if aimIsCtrl(r) {
			return ' '
		}
		return r
	}, aimStripLone(s))
	t = norm.NFC.String(t)
	var sb strings.Builder
	space := false
	for _, r := range t {
		if isJSSpace(r) {
			space = true
			continue
		}
		if space {
			sb.WriteByte(' ')
			space = false
		}
		sb.WriteRune(r)
	}
	// trailing whitespace is dropped (the loop only writes a separator before a following character); a leading run was a separator too
	t = jsTrim(sb.String())
	if len(t) <= maxBytes {
		return t
	}
	var out strings.Builder
	for _, r := range t {
		if out.Len()+utf8.RuneLen(r) > maxBytes {
			break
		}
		out.WriteRune(r)
	}
	return jsTrim(out.String())
}

func aimFirstText(max int, xs ...any) string {
	for _, x := range xs {
		if t := aimClip(x, max); len(t) > 0 {
			return t
		}
	}
	return ""
}

// ---- tokens and verbs ----------------------------------------------------------------------------------------------------

var (
	reAimCamel1 = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	reAimCamel2 = regexp.MustCompile(`([A-Z]+)([A-Z][a-z])`)
)

// aimTokensOf is the lowercase word tokens of a name: camelCase, snake, kebab, dotted and slashed names alike.
func aimTokensOf(name any) []string {
	s := norm.NFKD.String(aimJSString(name))
	s = strings.Map(func(r rune) rune {
		if r >= 0x300 && r <= 0x36F {
			return -1
		}
		return r
	}, s)
	s = reAimCamel2.ReplaceAllString(reAimCamel1.ReplaceAllString(s, "$1 $2"), "$1 $2")
	s = strings.ToLower(s)
	return strings.FieldsFunc(s, func(r rune) bool { return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) })
}

// aimJSString is String(v) of a JSON value.
func aimJSString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return jsValueString(v)
}

var aimActionWords = setOf("get", "list", "read", "fetch", "find", "search", "query", "show", "describe", "create", "add", "new", "make", "insert", "post", "put", "set", "update", "patch", "edit", "modify",
	"delete", "remove", "destroy", "drop", "send", "notify", "publish", "invite", "cancel", "refund", "charge", "pay", "run", "exec", "execute", "invoke", "start", "stop",
	"enable", "disable", "approve", "reject", "close", "open", "merge", "export", "import", "upload", "download", "subscribe", "unsubscribe", "revoke", "grant", "transfer")

func aimSeg(toks []string) string {
	s := strings.Join(toks, "_")
	if len(s) <= 32 {
		return s
	}
	// deterministic truncation: 27 chars + '_' + 4 hex of a digest of the whole segment
	h := sha256.Sum256([]byte(s))
	var d strings.Builder
	for _, r := range base64.RawURLEncoding.EncodeToString(h[:]) {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			d.WriteRune(r)
		}
	}
	x := strings.ToLower(d.String())
	if len(x) > 4 {
		x = x[:4]
	}
	for len(x) < 4 {
		x += "0"
	}
	return s[:27] + "_" + x
}

// aimVerbOf is a verb `<ns>.<noun...>.<action>` from a raw operation name.
func aimVerbOf(ns string, raw any) string {
	var parts [][]string
	for _, p := range strings.FieldsFunc(aimJSString(raw), func(r rune) bool { return r == '.' || r == '/' || r == ':' || isJSSpace(r) }) {
		if t := aimTokensOf(p); len(t) > 0 {
			parts = append(parts, t)
		}
	}
	var segs []string
	if len(parts) >= 2 {
		for _, p := range parts {
			segs = append(segs, aimSeg(p))
		}
	} else {
		t := []string{"op"}
		if len(parts) > 0 {
			t = parts[0]
		}
		switch {
		case len(t) >= 2 && aimActionWords[t[0]]:
			segs = []string{aimSeg(t[1:]), aimSeg(t[:1])}
		case len(t) >= 2 && aimActionWords[t[len(t)-1]]:
			segs = []string{aimSeg(t[:len(t)-1]), aimSeg(t[len(t)-1:])}
		default:
			segs = []string{aimSeg(t)}
		}
	}
	// at most 5 segments after the namespace: keep the first 2 and the last 3 (the action stays last)
	if len(segs) > 5 {
		segs = append(append([]string{}, segs[:2]...), segs[len(segs)-3:]...)
	}
	v := ns + "." + strings.Join(segs, ".")
	if !reVerb.MatchString(v) || len(v) > 128 {
		return ns + ".op"
	}
	return v
}

// aimAliasOf is the short NL-layer alias of a raw name (snake tokens); ok is false when it is not a valid alias or equals the verb.
func aimAliasOf(raw any, verb string) (string, bool) {
	a := strings.Join(aimTokensOf(raw), "_")
	if len(a) > 0 && len(a) <= 64 && reAlias.MatchString(a) && a != verb {
		return a, true
	}
	return "", false
}

// aimHumanize is "createCustomer" -> "Create customer": the title when the source gave none.
func aimHumanize(name any) string {
	t := aimTokensOf(name)
	if len(t) == 0 {
		return ""
	}
	return strings.Join(append([]string{strings.ToUpper(t[0][:1]) + t[0][1:]}, t[1:]...), " ")
}

// aimUniqueVerb makes verb unique inside the import (`_2`, `_3` on the last segment), noting the collision.
func aimUniqueVerb(c *aimCtx, verb, where string) string {
	if !c.verbs[verb] {
		return verb
	}
	for n := 2; n < 100_000; n++ {
		sfx := "_" + strconv.Itoa(n)
		dot := strings.LastIndex(verb, ".")
		last := verb[dot+1:]
		if k := 32 - len(sfx); len(last) > k {
			last = last[:k]
		}
		cand := verb[:dot+1] + last + sfx
		if !c.verbs[cand] && reVerb.MatchString(cand) {
			aimAddTodo(c, where, "duplicate_verb", "verb '"+verb+"' is taken by an earlier operation; this one is '"+cand+"'")
			return cand
		}
	}
	aimFail("import_limit", "too many operations map to one verb")
	return ""
}

// ---- JSON Schema: bounded resolution --------------------------------------------------------------------------------------

// aimBudget is the per-operation expansion budget: every schema node visited costs one; running out ends the expansion.
type aimBudget struct {
	left      int64
	exhausted bool
}

func aimNewBudget(c *aimCtx) *aimBudget { return &aimBudget{left: c.lim.maxRefNodes} }

func aimMergeAll(a, m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range m {
		out[k] = v
	}
	props := aimSpreadObj(a["properties"])
	for k, v := range aimSpreadObj(m["properties"]) {
		props[k] = v
	}
	out["properties"] = props
	req := aimSpreadArr(aimNullish(a["required"]))
	out["required"] = append(req, aimSpreadArr(aimNullish(m["required"]))...)
	return out
}

// aimNullish is `v ?? []` (a missing or null member is an empty array).
func aimNullish(v any) any {
	if v == nil {
		return []any{}
	}
	return v
}

func aimIsNullType(m map[string]any) bool {
	t, has := m["type"]
	if !has {
		return false
	}
	if aimStrEq(t, "null") {
		return true
	}
	a, ok := t.([]any)
	if !ok || len(a) == 0 {
		return false
	}
	for _, x := range a {
		if !aimStrEq(x, "null") {
			return false
		}
	}
	return true
}

func aimWithout(m map[string]any, drop ...string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	for _, d := range drop {
		delete(out, d)
	}
	return out
}

func aimOverlay(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}

func aimStrList(v any) ([]string, bool) {
	a, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(a))
	for i, x := range a {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

func aimDedupe(xs []string) []any {
	seen := map[string]bool{}
	out := []any{}
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// aimResolveSchema follows local `$ref`s, merges `allOf`, collapses `anyOf`/`oneOf` to the single non-null variant or to a union of
// string constants. What stays unrepresentable (a remote or cyclic reference, a real union, an exhausted budget) is noted and left
// as `{}`, which the caller declares `string`: a placeholder that rejects every non-string value, so the draft fails closed.
func aimResolveSchema(s any, c *aimCtx, bud *aimBudget, where string, chain []string, depth int64) map[string]any {
	cur, ok := s.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	if bud.left <= 0 {
		if !bud.exhausted {
			bud.exhausted = true
			aimAddTodo(c, where, "ref_budget", fmt.Sprintf("schema expansion stopped after %d nodes (declared string; refine or drop)", c.lim.maxRefNodes))
		}
		return map[string]any{}
	}
	bud.left--
	if depth > c.lim.maxRefDepth {
		aimAddTodo(c, where, "ref_depth", fmt.Sprintf("schema nesting or reference chain deeper than %d (declared string; refine or drop)", c.lim.maxRefDepth))
		return map[string]any{}
	}
	if ref, isRef := cur["$ref"].(string); isRef {
		if contains(chain, ref) {
			aimAddTodo(c, where, "cyclic_ref", "reference '"+aimClip(ref, 120)+"' is cyclic (declared string; refine or drop)")
			return map[string]any{}
		}
		target, found := aimPointer(c.root, ref)
		if !found {
			aimAddTodo(c, where, "unresolved_ref", "reference '"+aimClip(ref, 120)+"' is not a local reference that resolves (declared string; refine or drop)")
			return map[string]any{}
		}
		cur = aimOverlay(aimResolveSchema(target, c, bud, where, append(append([]string{}, chain...), ref), depth+1), aimWithout(cur, "$ref"))
	}
	if allOf, isArr := cur["allOf"].([]any); isArr {
		rest := aimWithout(cur, "allOf")
		resolved := make([]map[string]any, len(allOf))
		for i, m := range allOf {
			resolved[i] = aimResolveSchema(m, c, bud, where, chain, depth+1)
		}
		merged := map[string]any{}
		for _, m := range resolved {
			merged = aimMergeAll(merged, m)
		}
		cur = aimOverlay(merged, rest)
	}
	alts, isAlts := cur["anyOf"].([]any)
	if !isAlts {
		alts, isAlts = cur["oneOf"].([]any)
	}
	if isAlts {
		rest := aimWithout(cur, "anyOf", "oneOf")
		resolved := make([]map[string]any, len(alts))
		for i, m := range alts {
			resolved[i] = aimResolveSchema(m, c, bud, where, chain, depth+1)
		}
		var live []map[string]any
		for _, m := range resolved {
			if !aimIsNullType(m) {
				live = append(live, m)
			}
		}
		if len(live) == 1 {
			return aimOverlay(live[0], rest)
		}
		var all []string
		allConst := true
		for _, m := range live {
			if k, isS := m["const"].(string); isS {
				all = append(all, k)
			} else if es, isL := aimStrList(m["enum"]); isL {
				all = append(all, es...)
			} else {
				allConst = false
			}
		}
		if len(live) > 1 && allConst {
			return aimOverlay(rest, map[string]any{"type": "string", "enum": aimDedupe(all)})
		}
		aimAddTodo(c, where, "union", fmt.Sprintf("a union of %d schemas has no representation (declared string; refine or drop)", len(live)))
		return rest
	}
	if k, has := cur["const"].(string); has {
		if _, hasEnum := cur["enum"]; !hasEnum {
			cur = aimOverlay(cur, map[string]any{"enum": []any{k}})
		}
	}
	return cur
}

// ---- JSON Schema -> params ----------------------------------------------------------------------------------------------

var reAimParamBad = regexp.MustCompile(`[^A-Za-z0-9_]`)

// aimParamSeg is a param name segment: `[A-Za-z0-9_]{1,64}`; anything else is replaced by `_` (an astral character is two UTF-16 units, so two).
func aimParamSeg(raw string) string {
	var sb strings.Builder
	for _, u := range utf16Units(raw) {
		if u < 0x80 && !reAimParamBad.MatchString(string(rune(u))) {
			sb.WriteByte(byte(u))
		} else {
			sb.WriteByte('_')
		}
	}
	s := sb.String()
	if strings.Trim(s, "_") == "" {
		s = ""
	}
	if len(s) > 64 {
		s = s[:64]
	}
	if s == "" {
		return "p"
	}
	return s
}

var (
	aimFormats  = map[string]string{"email": "email", "uuid": "uuid", "uri": "url", "url": "url", "idn-email": "email", "semver": "semver"}
	aimReserved = setOf("__proto__", "constructor", "prototype")
	aimIntRoles = setOf("money.amount", "money.fee", "count.limit", "bytes.size")
)

func aimIsRoleOK(r string) bool {
	return contains(coreRoles, r) || reIDRole.MatchString(r) || reCustomRole.MatchString(r)
}

// aimIntNum is Number.isSafeInteger and not -0.
func aimIntNum(v any) (float64, bool) {
	f, ok := jsNum(v)
	if !ok || !jsIsInt(v) {
		return 0, false
	}
	return f, true
}

func aimNum(f float64) json.Number { return json.Number(jsNumberLexeme(f)) }

// aimEnumStrs is the enum as a deduplicated list of 1..256 plain strings, or nil.
func aimEnumStrs(e any) []any {
	a, ok := e.([]any)
	if !ok || len(a) == 0 || len(a) > 256 {
		return nil
	}
	ss := make([]string, len(a))
	for i, x := range a {
		s, isS := x.(string)
		if !isS || len(s) == 0 || utf8Len(s) > 256 || s != norm.NFC.String(s) || aimStripLone(s) != s {
			return nil
		}
		ss[i] = s
	}
	return aimDedupe(ss)
}

// aimFirstNonNull is `Array.isArray(t) ? t.find(x => x !== 'null') : t` over o.type; def is false for undefined.
func aimFirstNonNull(o map[string]any) (any, bool) {
	t, has := o["type"]
	if a, isArr := t.([]any); isArr {
		for _, x := range a {
			if !aimStrEq(x, "null") {
				return x, true
			}
		}
		return nil, false
	}
	return t, has
}

func aimCopyP(p map[string]any) map[string]any { return aimOverlay(p, nil) }

// aimLeafParam turns a leaf schema into a ParamDef. Unrepresentable shapes become `string` placeholders, noted.
func aimLeafParam(s map[string]any, required bool, c *aimCtx, bud *aimBudget, where string) map[string]any {
	t0, d0 := aimFirstNonNull(s)
	enumStr := aimEnumStrs(s["enum"])
	var t any
	tDef := false
	items, hasItems := s["items"]
	_, itemsObj := items.(map[string]any)
	_, itemsArr := items.([]any)
	switch {
	case d0 && t0 != nil:
		t, tDef = t0, true
	case enumStr != nil:
		t, tDef = "string", true
	case hasItems && (itemsObj || itemsArr):
		t, tDef = "array", true
	}
	base := map[string]any{"type": "string"}
	if !required {
		base["required"] = false
	}
	if desc := aimClip(s["description"], 280); len(desc) > 0 {
		base["description"] = desc
	}
	roleExt, hasRole := s["x-pca-role"].(string)
	hasRole = hasRole && c.ext["x-pca-role"]
	withRole := func(p map[string]any) map[string]any {
		if !hasRole {
			return p
		}
		if !aimIsRoleOK(roleExt) || (aimIntRoles[roleExt] && p["type"] != "integer") {
			aimAddTodo(c, where, "role_ignored", "x-pca-role '"+aimClip(roleExt, 64)+"' is not valid for a "+p["type"].(string)+" parameter")
			return p
		}
		p = aimCopyP(p)
		p["role"] = roleExt
		return p
	}
	typed := func(typ string, extra map[string]any) map[string]any {
		p := aimOverlay(base, extra)
		p["type"] = typ
		return p
	}
	fmtS, _ := s["format"].(string)
	if aimStrEq(t, "integer") || (aimStrEq(t, "number") && (fmtS == "int32" || fmtS == "int64")) {
		p := typed("integer", nil)
		exMin, exMax := s["exclusiveMinimum"], s["exclusiveMaximum"]
		var mn, mx *float64
		setf := func(f float64) *float64 { return &f }
		if f, ok := aimIntNum(s["minimum"]); ok && exMin != true {
			mn = setf(f)
		} else if g, ok2 := aimIntNum(exMin); ok2 {
			mn = setf(g + 1)
		} else if ok && exMin == true {
			mn = setf(f + 1)
		}
		if f, ok := aimIntNum(s["maximum"]); ok && exMax != true {
			mx = setf(f)
		} else if g, ok2 := aimIntNum(exMax); ok2 {
			mx = setf(g - 1)
		} else if ok && exMax == true {
			mx = setf(f - 1)
		}
		if mn != nil && mx != nil && *mn > *mx {
			mn, mx = nil, nil
		}
		if mn != nil {
			p["min"] = aimNum(*mn)
		}
		if mx != nil {
			p["max"] = aimNum(*mx)
		}
		return withRole(p)
	}
	if aimStrEq(t, "boolean") {
		return withRole(typed("boolean", nil))
	}
	if aimStrEq(t, "string") {
		switch fmtS {
		case "date":
			return withRole(typed("date", nil))
		case "date-time":
			return withRole(typed("datetime", nil))
		}
		p := typed("string", nil)
		if enumStr != nil {
			p["values"] = enumStr
		} else if e, isArr := s["enum"].([]any); isArr && len(e) > 0 {
			aimAddTodo(c, where, "enum_dropped", "enum values are not 1..256 plain strings (declared as a free string; refine)")
		}
		if f, ok := aimFormats[fmtS]; ok {
			p["format"] = f
		}
		if f, ok := aimIntNum(s["maxLength"]); ok && f > 0 && f <= 16_777_216 {
			p["max_len"] = aimNum(f)
		}
		return withRole(p)
	}
	if aimStrEq(t, "array") {
		it := aimResolveSchema(s["items"], c, bud, where+"[]", nil, 0)
		itEnum := aimEnumStrs(it["enum"])
		lim := map[string]any{}
		maxI, hasMax := aimIntNum(s["maxItems"])
		hasMax = hasMax && maxI >= 0
		minI, hasMin := aimIntNum(s["minItems"])
		hasMin = hasMin && minI >= 0
		if hasMax && hasMin && minI > maxI {
			hasMax, hasMin = false, false
		}
		if hasMax {
			lim["max_items"] = aimNum(maxI)
		}
		if hasMin {
			lim["min_items"] = aimNum(minI)
		}
		if aimIsTrue(s["uniqueItems"]) && itEnum != nil {
			p := typed("set", lim)
			p["values"] = itEnum
			return withRole(p)
		}
		itT, itDef := aimFirstNonNull(it)
		item := ""
		for _, k := range []string{"integer", "string", "boolean"} {
			if aimStrEq(itT, k) {
				item = k
			}
		}
		if item == "" && itDef {
			aimAddTodo(c, where, "array_items", "array items of type '"+aimClip(aimJSString(itT), 40)+"' are not declared (items left open)")
		}
		p := typed("array", lim)
		if item != "" {
			p["items"] = item
		}
		return withRole(p)
	}
	if aimStrEq(t, "number") {
		aimAddTodo(c, where, "unsupported_type", "type 'number' (fractions) has no ActionDef representation (declared string; use an integer unit, or refine)")
	} else {
		shown := "none"
		if tDef {
			shown = aimJSString(t)
		}
		aimAddTodo(c, where, "unsupported_type", "type '"+aimClip(shown, 40)+"' has no representation (declared string; refine or drop)")
	}
	return withRole(typed("string", nil))
}

// aimFlattenObject flattens an object schema into params: nested objects become dotted names up to maxParamPathDepth segments, an
// object below that (or without properties) is a `string` placeholder; a child of an optional parent is optional. At most
// maxDefParams params; the rest are dropped, noted.
func aimFlattenObject(schema map[string]any, c *aimCtx, bud *aimBudget, where string, out map[string]any, prefix []string, parentRequired bool) {
	props, _ := schema["properties"].(map[string]any)
	req := map[string]bool{}
	if r, ok := schema["required"].([]any); ok {
		for _, x := range r {
			if s, isS := x.(string); isS {
				req[s] = true
			}
		}
	}
	for _, name := range aimSortedKeys(props) {
		if aimReserved[name] {
			aimAddTodo(c, where+": "+name, "skipped_param", "parameter name '"+name+"' is reserved; dropped")
			continue
		}
		child := aimResolveSchema(props[name], c, bud, where+": "+name, nil, 0)
		if aimIsTrue(child["readOnly"]) {
			continue // response-only; not an input
		}
		sname := aimParamSeg(name)
		if sname != name {
			aimAddTodo(c, where+": "+name, "renamed_param", "parameter '"+aimClip(name, 80)+"' is declared as '"+sname+"'")
		}
		path := append(append([]string{}, prefix...), sname)
		full := strings.Join(path, ".")
		required := parentRequired && req[name]
		cprops, cpropsObj := child["properties"].(map[string]any)
		ct, hasT := child["type"]
		isObject := aimStrEq(ct, "object") || (!hasT && cpropsObj)
		if isObject && cpropsObj && len(cprops) > 0 && len(path) < maxParamPathDepth {
			aimFlattenObject(child, c, bud, where+": "+full, out, path, required)
			continue
		}
		if len(out) >= maxDefParams {
			aimAddTodo(c, where, "too_many_params", fmt.Sprintf("more than %d parameters; '%s' and the rest are dropped", maxDefParams, full))
			return
		}
		collide := false
		if _, has := out[full]; has {
			collide = true
		}
		for k := range out {
			if strings.HasPrefix(k, full+".") || strings.HasPrefix(full, k+".") {
				collide = true
			}
		}
		if collide {
			aimAddTodo(c, where+": "+full, "skipped_param", "parameter '"+full+"' collides with another; kept the first")
			continue
		}
		if isObject {
			out[full] = aimPlaceholderObject(child, required, c, where+": "+full)
		} else {
			out[full] = aimLeafParam(child, required, c, bud, where+": "+full)
		}
	}
}

func aimPlaceholderObject(s map[string]any, required bool, c *aimCtx, where string) map[string]any {
	aimAddTodo(c, where, "object_leaf", "an object with no (or too deeply nested) properties has no representation (declared string; refine or drop)")
	p := map[string]any{"type": "string"}
	if !required {
		p["required"] = false
	}
	if d := aimClip(s["description"], 280); len(d) > 0 {
		p["description"] = d
	}
	return p
}

// ---- assembling a draft def -----------------------------------------------------------------------------------------------

// aimDraft is one operation before it is assembled: name is the raw operation name; title and description are raw source values.
type aimDraft struct {
	name        string
	verb        string // "" = derive from name
	title       any
	description any
	effects     []string
	scope       string
	params      map[string]any
	idempotency map[string]any
	traits      []string
	noAlias     bool
	bindings    map[string]any
}

var reAimResourceType = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,4}$`)

// aimEmitDef assembles, validates and registers a draft def. A def that fails validation is dropped, noted (never emitted).
func aimEmitDef(c *aimCtx, d aimDraft) map[string]any {
	if int64(len(c.defs)) >= c.lim.maxOps {
		aimFail("import_limit", fmt.Sprintf("more than %d operations", c.lim.maxOps))
	}
	rawVerb := d.verb
	if rawVerb == "" {
		rawVerb = aimVerbOf(c.ns, d.name)
	}
	if !reVerb.MatchString(rawVerb) {
		rawVerb = aimVerbOf(c.ns, d.name)
	}
	verb := aimUniqueVerb(c, rawVerb, d.name)
	segs := strings.Split(verb, ".")
	rtype := segs[0]
	if len(segs) > 2 {
		rtype = strings.Join(segs[:len(segs)-1], ".")
	}
	title := aimFirstText(maxDefTitleBytes, d.title, aimHumanize(d.name), verb)
	description := aimClip(d.description, 600)
	def := map[string]any{"v": json.Number("1"), "kind": actionDefKind, "verb": verb}
	if !d.noAlias {
		if alias, ok := aimAliasOf(d.name, verb); ok {
			if _, taken := c.aliases[alias]; !taken && !c.verbs[alias] {
				def["aliases"] = []any{alias}
			}
		}
	}
	if title == "" {
		title = verb
	}
	def["title"] = title
	if description != "" {
		def["description"] = description
	}
	eff := append([]string{}, d.effects...)
	sort.Strings(eff)
	def["effects"] = aimDedupe(eff)
	if !reAimResourceType.MatchString(rtype) {
		rtype = segs[0]
	}
	def["resource"] = map[string]any{"type": rtype, "id": map[string]any{"prefix": "", "class": "any_safe", "len": []any{json.Number("1"), json.Number("128")}}, "scope": d.scope}
	def["params"] = d.params
	if d.idempotency != nil {
		def["idempotency"] = d.idempotency
	}
	if len(d.traits) > 0 {
		tr := append([]string{}, d.traits...)
		sort.Strings(tr)
		def["traits"] = aimDedupe(tr)
	}
	def["bindings"] = d.bindings
	def["review"] = map[string]any{"state": "unreviewed"}
	def["source"] = c.source.asMap()
	if bad := validateDef(def); bad != "" {
		aimAddTodo(c, d.name, "invalid_def", "not emitted: "+bad)
		return nil
	}
	c.verbs[verb] = true
	if al, ok := def["aliases"].([]any); ok {
		c.aliases[al[0].(string)] = verb
	}
	c.defs = append(c.defs, def)
	return def
}

// aimWithTrait adds a declared trait to a draft (used for hint-derived traits such as network egress).
func aimWithTrait(traits []string, t string) []string {
	for _, x := range traits {
		if x == t {
			return traits
		}
	}
	return append(append([]string{}, traits...), t)
}
