package pca

// Token-tape form of the Goal IR (the TypeScript reference is @atlasauth/pca-goal `codec`). A tape is a slice of GoalTok
// (keyword number | integer | string). Encoding is STRICT: anything that is not exactly an IR value panics with *GoalIrError (or the
// *anlThrow a JavaScript property read of null would), so a malformed value never reaches a parser as something that merely
// happens to parse. IR values are the JSON trees of the reference (map[string]any with a `k` discriminant, json.Number numbers).
// The goal* functions panic; the exported Goal* wrappers return errors.

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
)

// GoalTok is one tape token: Tag 'k' (keyword), 'i' (integer) or 's' (string).
type GoalTok struct {
	Tag byte
	Int int64
	Str string
}

// GoalTape is a token tape.
type GoalTape = []GoalTok

// MarshalJSON renders the reference's [tag, value] pair.
func (t GoalTok) MarshalJSON() ([]byte, error) {
	if t.Tag == 's' {
		s, err := json.Marshal(t.Str)
		if err != nil {
			return nil, err
		}
		return append(append([]byte(`["s",`), s...), ']'), nil
	}
	return []byte(`["` + string(t.Tag) + `",` + strconv.FormatInt(t.Int, 10) + `]`), nil
}

// GoalIrError is the reference's IrError.
type GoalIrError struct{ msg string }

func (e *GoalIrError) Error() string { return "pca-goal: " + e.msg }

func goalFail(format string, a ...any) { panic(&GoalIrError{fmt.Sprintf(format, a...)}) }

// goalNum is the JSON number of an integer.
func goalNum(n int64) json.Number { return json.Number(strconv.FormatInt(n, 10)) }

func goalK(n int64) GoalTok { return GoalTok{Tag: 'k', Int: n} }

func goalI(v any) GoalTok {
	f, ok := jsNum(v)
	if !ok || f != math.Trunc(f) || math.Abs(f) > maxSafeInt || (f == 0 && math.Signbit(f)) {
		goalFail("%s is not a safe integer", anlJS(v))
	}
	return GoalTok{Tag: 'i', Int: int64(f)}
}

func goalIn(n int) GoalTok { return GoalTok{Tag: 'i', Int: int64(n)} }

func goalS(v any) GoalTok {
	s, ok := v.(string)
	if !ok {
		goalFail("string expected")
	}
	return GoalTok{Tag: 's', Str: s}
}

func goalBad(what string, v any) {
	goalFail("unknown %s: %s", what, anlJSON(v))
}

func goalCat(parts ...[]GoalTok) []GoalTok {
	var out []GoalTok
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func goalList(xs any, f func(any) []GoalTok) []GoalTok {
	l, ok := xs.([]any)
	if !ok {
		goalFail("array expected")
	}
	out := []GoalTok{goalIn(len(l))}
	for _, x := range l {
		out = append(out, f(x)...)
	}
	return out
}

func goalStrs(xs any) []GoalTok {
	return goalList(xs, func(s any) []GoalTok { return []GoalTok{goalS(s)} })
}

// goalStrOf is `typeof v === 'string'` plus the value.
func goalStrOf(v any) (string, bool) { s, ok := v.(string); return s, ok }

var (
	goalOps      = []string{"eq", "ne", "lt", "lte", "gt", "gte", "in", "nin"}
	goalAggs     = []string{"count", "sum", "max", "distinct"}
	goalUnitTags = map[string]int64{"count": 301, "duration": 302, "instant": 303, "bytes": 304, "ratio": 305}
)

func goalIndexOf(xs []string, v any) int {
	s, ok := v.(string)
	if !ok {
		return -1
	}
	for i, x := range xs {
		if x == s {
			return i
		}
	}
	return -1
}

func goalEncUnit(u any) []GoalTok {
	k := anlGet(u, "k")
	if k == "money" {
		return []GoalTok{goalK(300), goalS(anlGet(u, "ccy"))}
	}
	if s, ok := k.(string); ok {
		if n, ok := goalUnitTags[s]; ok {
			return []GoalTok{goalK(n)}
		}
	}
	goalBad("unit", u)
	return nil
}

func goalEncQ(q any) []GoalTok {
	return goalCat(goalEncUnit(anlGet(q, "u")), []GoalTok{goalI(anlGet(q, "n"))})
}

func goalEncTy(t any) []GoalTok {
	k := anlGet(t, "k")
	if k == "q" {
		return goalCat([]GoalTok{goalK(310)}, goalEncUnit(anlGet(t, "u")))
	}
	if k == "s" {
		return []GoalTok{goalK(311)}
	}
	goalBad("type", t)
	return nil
}

func goalEncAtom(a any) []GoalTok {
	k := anlGet(a, "k")
	if k == "q" {
		return goalCat([]GoalTok{goalK(320)}, goalEncQ(anlGet(a, "q")))
	}
	if k == "s" {
		return []GoalTok{goalK(321), goalS(anlGet(a, "s"))}
	}
	goalBad("set member (sets hold quantities and strings only)", a)
	return nil
}

func goalEncV(v any) []GoalTok {
	switch anlGet(v, "k") {
	case "q":
		return goalCat([]GoalTok{goalK(330)}, goalEncQ(anlGet(v, "q")))
	case "s":
		return []GoalTok{goalK(331), goalS(anlGet(v, "s"))}
	case "set":
		return goalCat([]GoalTok{goalK(332)}, goalList(anlGet(v, "items"), goalEncAtom))
	}
	goalBad("value", v)
	return nil
}

func goalEncTerm(t any) []GoalTok {
	switch anlGet(t, "k") {
	case "param":
		return goalCat([]GoalTok{goalK(340), goalS(anlGet(t, "path"))}, goalEncTy(anlGet(t, "ty")))
	case "lit":
		return goalCat([]GoalTok{goalK(341)}, goalEncV(anlGet(t, "v")))
	case "hist":
		return goalCat([]GoalTok{goalK(342), goalS(anlGet(t, "bid"))}, goalEncUnit(anlGet(t, "u")))
	}
	goalBad("term", t)
	return nil
}

func goalEncOp(op any) []GoalTok {
	if i := goalIndexOf(goalOps, op); i >= 0 {
		return []GoalTok{goalK(int64(350 + i))}
	}
	goalBad("operator", op)
	return nil
}

func goalEncCond(c any) []GoalTok {
	switch anlGet(c, "k") {
	case "true":
		return []GoalTok{goalK(360)}
	case "cmp":
		return goalCat([]GoalTok{goalK(361)}, goalEncOp(anlGet(c, "op")), goalEncTerm(anlGet(c, "l")), goalEncTerm(anlGet(c, "r")))
	case "and":
		return goalCat([]GoalTok{goalK(362)}, goalEncCond(anlGet(c, "a")), goalEncCond(anlGet(c, "b")))
	case "or":
		return goalCat([]GoalTok{goalK(363)}, goalEncCond(anlGet(c, "a")), goalEncCond(anlGet(c, "b")))
	case "not":
		return goalCat([]GoalTok{goalK(364)}, goalEncCond(anlGet(c, "c")))
	}
	goalBad("condition", c)
	return nil
}

func goalEncPart(s any) []GoalTok {
	switch anlGet(s, "k") {
	case "exact":
		return []GoalTok{goalK(375), goalS(anlGet(s, "id"))}
	case "oneof":
		return goalCat([]GoalTok{goalK(376)}, goalStrs(anlGet(s, "ids")))
	case "related":
		return []GoalTok{goalK(377), goalS(anlGet(s, "rel")), goalS(anlGet(s, "anchor"))}
	}
	goalBad("resource part", s)
	return nil
}

func goalEncRes(s any) []GoalTok {
	switch anlGet(s, "k") {
	case "exact":
		return []GoalTok{goalK(370), goalS(anlGet(s, "id"))}
	case "oneof":
		return goalCat([]GoalTok{goalK(371)}, goalStrs(anlGet(s, "ids")))
	case "related":
		return []GoalTok{goalK(372), goalS(anlGet(s, "rel")), goalS(anlGet(s, "anchor"))}
	case "any":
		return []GoalTok{goalK(373), goalS(anlGet(s, "reason"))}
	case "all_of":
		return goalCat([]GoalTok{goalK(374)}, goalList(anlGet(s, "parts"), goalEncPart))
	}
	goalBad("resource selector", s)
	return nil
}

func goalEncGrant(g any) []GoalTok {
	return goalCat([]GoalTok{goalK(380), goalS(anlGet(g, "gid")), goalS(anlGet(g, "verb"))}, goalEncRes(anlGet(g, "res")), goalEncCond(anlGet(g, "cond")))
}

func goalEncTarget(t any) []GoalTok {
	switch anlGet(t, "k") {
	case "verb":
		return []GoalTok{goalK(390), goalS(anlGet(t, "verb"))}
	case "effect":
		return []GoalTok{goalK(391), goalS(anlGet(t, "cls"))}
	}
	goalBad("prohibit target", t)
	return nil
}

func goalEncProhibit(p any) []GoalTok {
	return goalCat([]GoalTok{goalK(392), goalS(anlGet(p, "pid"))}, goalEncTarget(anlGet(p, "target")), goalEncRes(anlGet(p, "res")), goalEncCond(anlGet(p, "cond")))
}

func goalEncSel(s any) []GoalTok {
	switch anlGet(s, "k") {
	case "gids":
		return goalCat([]GoalTok{goalK(410)}, goalStrs(anlGet(s, "gids")))
	case "effect":
		return []GoalTok{goalK(411), goalS(anlGet(s, "cls"))}
	}
	goalBad("selection", s)
	return nil
}

func goalEncWindow(w any) []GoalTok {
	switch anlGet(w, "k") {
	case "task":
		return []GoalTok{goalK(420)}
	case "sliding":
		return []GoalTok{goalK(421), goalI(anlGet(w, "ms"))}
	case "period":
		return []GoalTok{goalK(422), goalI(anlGet(w, "ms")), goalI(anlGet(w, "t0"))}
	case "lifetime":
		return []GoalTok{goalK(423)}
	}
	goalBad("window", w)
	return nil
}

func goalEncScope(s any) []GoalTok {
	switch anlGet(s, "k") {
	case "session":
		return []GoalTok{goalK(430)}
	case "principal":
		return []GoalTok{goalK(431)}
	case "org":
		return []GoalTok{goalK(432)}
	case "fleet":
		return goalCat([]GoalTok{goalK(433)}, goalStrs(anlGet(s, "agents")))
	}
	goalBad("scope", s)
	return nil
}

func goalEncOnExceed(o any) []GoalTok {
	switch o {
	case "deny":
		return []GoalTok{goalK(440)}
	case "escalate":
		return []GoalTok{goalK(441)}
	}
	goalBad("on_exceed", o)
	return nil
}

func goalEncBCore(b any) []GoalTok {
	agg := anlGet(b, "agg")
	i := goalIndexOf(goalAggs, agg)
	if i < 0 {
		goalBad("aggregate", agg)
	}
	return goalCat([]GoalTok{goalK(450), goalK(int64(400 + i))}, goalEncTerm(anlGet(b, "value")), []GoalTok{goalS(anlGet(b, "key"))},
		goalEncWindow(anlGet(b, "window")), goalEncScope(anlGet(b, "scope")), goalEncQ(anlGet(b, "cap")), goalEncOnExceed(anlGet(b, "onExceed")))
}

func goalEncBound(b any) []GoalTok {
	return goalCat([]GoalTok{goalK(451), goalS(anlGet(b, "bid"))}, goalEncSel(anlGet(b, "sel")), goalEncBCore(b))
}

func goalEncValidity(v any) []GoalTok {
	return []GoalTok{goalK(460), goalI(anlGet(v, "notBefore")), goalI(anlGet(v, "notAfter")), goalI(anlGet(v, "maxIdle"))}
}

func goalBit(v any) GoalTok {
	if anlTruthy(v) {
		return goalIn(1)
	}
	return goalIn(0)
}

func goalEncDeleg(d any) []GoalTok {
	return goalCat([]GoalTok{goalK(461), goalI(anlGet(d, "maxDepth")), goalBit(anlGet(d, "narrowOnly"))}, goalStrs(anlGet(d, "mayTouch")))
}

func goalEncHole(h any) []GoalTok {
	return goalCat([]GoalTok{goalK(470), goalS(anlGet(h, "hid")), goalS(anlGet(h, "q"))}, goalStrs(anlGet(h, "domain")), goalStrs(anlGet(h, "affects")), []GoalTok{goalBit(anlGet(h, "global"))})
}

// goalEncodeGoal is the goal as a token tape.
func goalEncodeGoal(g any) GoalTape {
	return goalCat([]GoalTok{goalK(480), goalI(anlGet(g, "v")), goalS(anlGet(g, "principal")), goalS(anlGet(g, "ontDigest")), goalS(anlGet(g, "nlDigest"))},
		goalStrs(anlGet(g, "sources")), goalList(anlGet(g, "grants"), goalEncGrant), goalList(anlGet(g, "prohibits"), goalEncProhibit),
		goalList(anlGet(g, "bounds"), goalEncBound), goalEncValidity(anlGet(g, "validity")), goalEncDeleg(anlGet(g, "deleg")),
		goalList(anlGet(g, "escalateOn"), goalEncCond), goalStrs(anlGet(g, "wildcardAck")), goalList(anlGet(g, "holes"), goalEncHole))
}

func goalEncParamDecl(p any) []GoalTok {
	return goalCat([]GoalTok{goalK(500), goalS(anlGet(p, "path"))}, goalEncTy(anlGet(p, "ty")))
}

func goalEncVerbDecl(v any) []GoalTok {
	return goalCat([]GoalTok{goalK(501), goalS(anlGet(v, "verb")), goalS(anlGet(v, "cls"))}, goalList(anlGet(v, "params"), goalEncParamDecl))
}

func goalEncRelDecl(r any) []GoalTok {
	return goalCat([]GoalTok{goalK(502), goalS(anlGet(r, "rel")), goalS(anlGet(r, "anchor"))}, goalStrs(anlGet(r, "members")))
}

func goalEncodeOntology(o any) GoalTape {
	return goalCat([]GoalTok{goalK(510)}, goalList(anlGet(o, "verbs"), goalEncVerbDecl), goalList(anlGet(o, "rels"), goalEncRelDecl))
}

// goalOkeys is Object.keys(o) for the value kinds the codec meets: an object's keys (JS order), an array's indices, nothing else;
// null / undefined throw.
func goalOkeys(o any) []string {
	switch t := o.(type) {
	case nil:
		anlFail("cannot convert undefined or null to object")
	case map[string]any:
		return jsKeys(t)
	case []any:
		out := make([]string, len(t))
		for i := range t {
			out[i] = strconv.Itoa(i)
		}
		return out
	case string:
		n := jsLen(t)
		out := make([]string, n)
		for i := 0; i < n; i++ {
			out[i] = strconv.Itoa(i)
		}
		return out
	}
	if anlIsUndef(o) {
		anlFail("cannot convert undefined or null to object")
	}
	return nil
}

// goalOget is o[k] for an object (undefined when absent) or an array index.
func goalOget(o any, k string) any {
	switch t := o.(type) {
	case map[string]any:
		if v, ok := t[k]; ok {
			return v
		}
	case []any:
		if i, err := strconv.Atoi(k); err == nil && i >= 0 && i < len(t) {
			return t[i]
		}
	}
	return anlUndef
}

// goalSortU16 sorts strings by UTF-16 code units (JavaScript default sort).
func goalSortU16(xs []string) []string {
	out := append([]string(nil), xs...)
	sort.SliceStable(out, func(i, j int) bool { return utf16Less(out[i], out[j]) })
	return out
}

func goalEncAct(a any) []GoalTok {
	params := anlGet(a, "params")
	keys := goalSortU16(goalOkeys(params))
	ks := make([]any, len(keys))
	for i, k := range keys {
		ks[i] = k
	}
	return goalCat([]GoalTok{goalK(530), goalS(anlGet(a, "verb")), goalS(anlGet(a, "res"))},
		goalList(ks, func(k any) []GoalTok {
			return goalCat([]GoalTok{goalK(520), goalS(k)}, goalEncV(goalOget(params, k.(string))))
		}),
		[]GoalTok{goalI(anlGet(a, "t")), goalS(anlGet(a, "sess")), goalS(anlGet(a, "prin")), goalS(anlGet(a, "org")), goalS(anlGet(a, "agent")), goalI(anlGet(a, "depth"))})
}

func goalEncodeAct(a any) GoalTape { return goalEncAct(a) }

func goalEncAdm(a any) []GoalTok {
	return goalCat([]GoalTok{goalK(531), goalS(anlGet(a, "gid"))}, goalEncAct(anlGet(a, "act")))
}

func goalEncodeHist(h any) GoalTape {
	aggs := anlGet(h, "aggs")
	keys := goalSortU16(goalOkeys(aggs))
	ks := make([]any, len(keys))
	for i, k := range keys {
		ks[i] = k
	}
	return goalCat([]GoalTok{goalK(541)}, goalList(anlGet(h, "adms"), goalEncAdm), []GoalTok{goalI(anlGet(h, "last"))},
		goalList(ks, func(k any) []GoalTok {
			return goalCat([]GoalTok{goalK(540), goalS(k)}, goalEncQ(goalOget(aggs, k.(string))))
		}))
}

// ---- decoding ----

// GoalTapeReader reads a tape.
type GoalTapeReader struct {
	t []GoalTok
	i int
}

func (r *GoalTapeReader) next() GoalTok {
	if r.i >= len(r.t) {
		goalFail("truncated tape")
	}
	x := r.t[r.i]
	r.i++
	return x
}

func (r *GoalTapeReader) k() int64 {
	x := r.next()
	if x.Tag != 'k' {
		goalFail("keyword expected")
	}
	return x.Int
}

func (r *GoalTapeReader) int() int64 {
	x := r.next()
	if x.Tag != 'i' {
		goalFail("integer expected")
	}
	return x.Int
}

func (r *GoalTapeReader) str() string {
	x := r.next()
	if x.Tag != 's' {
		goalFail("string expected")
	}
	return x.Str
}

func (r *GoalTapeReader) done() bool { return r.i >= len(r.t) }

func (r *GoalTapeReader) list(f func() any) []any {
	n := r.int()
	if n < 0 {
		goalFail("negative length")
	}
	out := []any{}
	for j := int64(0); j < n; j++ {
		out = append(out, f())
	}
	return out
}

func (r *GoalTapeReader) strs() []any { return r.list(func() any { return r.str() }) }

var goalUnitNames = map[int64]string{301: "count", 302: "duration", 303: "instant", 304: "bytes", 305: "ratio"}

func goalDUnit(r *GoalTapeReader) map[string]any {
	k := r.k()
	if k == 300 {
		return map[string]any{"k": "money", "ccy": r.str()}
	}
	n, ok := goalUnitNames[k]
	if !ok {
		goalFail("bad unit tag %d", k)
	}
	return map[string]any{"k": n}
}

func goalDQ(r *GoalTapeReader) map[string]any {
	u := goalDUnit(r)
	return map[string]any{"u": u, "n": goalNum(r.int())}
}

func goalDTy(r *GoalTapeReader) map[string]any {
	k := r.k()
	if k == 310 {
		return map[string]any{"k": "q", "u": goalDUnit(r)}
	}
	if k == 311 {
		return map[string]any{"k": "s"}
	}
	goalFail("bad type tag %d", k)
	return nil
}

func goalDAtom(r *GoalTapeReader) any {
	k := r.k()
	if k == 320 {
		return map[string]any{"k": "q", "q": goalDQ(r)}
	}
	if k == 321 {
		return map[string]any{"k": "s", "s": r.str()}
	}
	goalFail("bad atom tag %d", k)
	return nil
}

func goalDV(r *GoalTapeReader) map[string]any {
	k := r.k()
	switch k {
	case 330:
		return map[string]any{"k": "q", "q": goalDQ(r)}
	case 331:
		return map[string]any{"k": "s", "s": r.str()}
	case 332:
		return map[string]any{"k": "set", "items": r.list(func() any { return goalDAtom(r) })}
	}
	goalFail("bad value tag %d", k)
	return nil
}

func goalDTerm(r *GoalTapeReader) map[string]any {
	k := r.k()
	switch k {
	case 340:
		path := r.str()
		return map[string]any{"k": "param", "path": path, "ty": goalDTy(r)}
	case 341:
		return map[string]any{"k": "lit", "v": goalDV(r)}
	case 342:
		bid := r.str()
		return map[string]any{"k": "hist", "bid": bid, "u": goalDUnit(r)}
	}
	goalFail("bad term tag %d", k)
	return nil
}

func goalDOp(r *GoalTapeReader) string {
	i := r.k() - 350
	if i >= 0 && i < int64(len(goalOps)) {
		return goalOps[i]
	}
	goalFail("bad operator")
	return ""
}

func goalDN(r *GoalTapeReader) map[string]any {
	k := r.k()
	switch k {
	case 600:
		return map[string]any{"k": "true"}
	case 601:
		return map[string]any{"k": "false"}
	case 602:
		op := goalDOp(r)
		l := goalDTerm(r)
		return map[string]any{"k": "atom", "op": op, "l": l, "r": goalDTerm(r)}
	case 603:
		a := goalDN(r)
		return map[string]any{"k": "and", "a": a, "b": goalDN(r)}
	case 604:
		a := goalDN(r)
		return map[string]any{"k": "or", "a": a, "b": goalDN(r)}
	}
	goalFail("bad condition tag %d", k)
	return nil
}

func goalDResPat(r *GoalTapeReader) map[string]any {
	k := r.k()
	if k == 630 {
		return map[string]any{"k": "star"}
	}
	if k == 631 {
		return map[string]any{"k": "set", "ids": r.strs()}
	}
	goalFail("bad resource pattern tag %d", k)
	return nil
}

func goalDWindow(r *GoalTapeReader) map[string]any {
	k := r.k()
	switch k {
	case 420:
		return map[string]any{"k": "task"}
	case 421:
		return map[string]any{"k": "sliding", "ms": goalNum(r.int())}
	case 422:
		ms := r.int()
		return map[string]any{"k": "period", "ms": goalNum(ms), "t0": goalNum(r.int())}
	case 423:
		return map[string]any{"k": "lifetime"}
	}
	goalFail("bad window tag %d", k)
	return nil
}

func goalDScope(r *GoalTapeReader) map[string]any {
	k := r.k()
	switch k {
	case 430:
		return map[string]any{"k": "session"}
	case 431:
		return map[string]any{"k": "principal"}
	case 432:
		return map[string]any{"k": "org"}
	case 433:
		return map[string]any{"k": "fleet", "agents": r.strs()}
	}
	goalFail("bad scope tag %d", k)
	return nil
}

func goalDAgg(r *GoalTapeReader) string {
	i := r.k() - 400
	if i >= 0 && i < int64(len(goalAggs)) {
		return goalAggs[i]
	}
	goalFail("bad aggregate")
	return ""
}

func goalDOnExceed(r *GoalTapeReader) string {
	oe := r.k()
	if oe != 440 && oe != 441 {
		goalFail("bad on_exceed")
	}
	if oe == 440 {
		return "deny"
	}
	return "escalate"
}

func goalDCeil(r *GoalTapeReader) map[string]any {
	if r.k() != 610 {
		goalFail("ceiling expected")
	}
	bid := r.str()
	selGids := r.strs()
	selVerbs := r.strs()
	if r.k() != 450 {
		goalFail("bound core expected")
	}
	agg := goalDAgg(r)
	value := goalDTerm(r)
	key := r.str()
	window := goalDWindow(r)
	scope := goalDScope(r)
	capQ := goalDQ(r)
	return map[string]any{"bid": bid, "selGids": selGids, "selVerbs": selVerbs, "agg": agg, "value": value, "key": key, "window": window,
		"scope": scope, "cap": capQ, "onExceed": goalDOnExceed(r)}
}

// goalDecodePolicy decodes the compiler's policy tape (after its leading status token); panics unless the whole tape is one policy.
func goalDecodePolicy(t GoalTape) map[string]any {
	r := &GoalTapeReader{t: t}
	if r.k() != 650 {
		goalFail("policy expected")
	}
	pred := func() any {
		if r.k() != 620 {
			goalFail("pred")
		}
		gid := r.str()
		verb := r.str()
		res := goalDResPat(r)
		return map[string]any{"gid": gid, "verb": verb, "res": res, "cond": goalDN(r)}
	}
	proh := func() any {
		if r.k() != 640 {
			goalFail("prohibition")
		}
		pid := r.str()
		verbs := r.strs()
		res := goalDResPat(r)
		return map[string]any{"pid": pid, "verbs": verbs, "res": res, "cond": goalDN(r)}
	}
	preds := r.list(pred)
	prohs := r.list(proh)
	ceils := r.list(func() any { return goalDCeil(r) })
	escs := r.list(func() any { return goalDN(r) })
	if r.k() != 460 {
		goalFail("validity")
	}
	nb := r.int()
	na := r.int()
	validity := map[string]any{"notBefore": goalNum(nb), "notAfter": goalNum(na), "maxIdle": goalNum(r.int())}
	if r.k() != 461 {
		goalFail("delegation")
	}
	md := r.int()
	nrw := r.int() == 1
	deleg := map[string]any{"maxDepth": goalNum(md), "narrowOnly": nrw, "mayTouch": r.strs()}
	if !r.done() {
		goalFail("trailing tokens after policy")
	}
	return map[string]any{"preds": preds, "prohs": prohs, "ceils": ceils, "escs": escs, "validity": validity, "deleg": deleg}
}

func goalDCond(r *GoalTapeReader) map[string]any {
	k := r.k()
	switch k {
	case 360:
		return map[string]any{"k": "true"}
	case 361:
		op := goalDOp(r)
		l := goalDTerm(r)
		return map[string]any{"k": "cmp", "op": op, "l": l, "r": goalDTerm(r)}
	case 362:
		a := goalDCond(r)
		return map[string]any{"k": "and", "a": a, "b": goalDCond(r)}
	case 363:
		a := goalDCond(r)
		return map[string]any{"k": "or", "a": a, "b": goalDCond(r)}
	case 364:
		return map[string]any{"k": "not", "c": goalDCond(r)}
	}
	goalFail("bad condition tag %d", k)
	return nil
}

func goalDPart(r *GoalTapeReader) any {
	k := r.k()
	switch k {
	case 375:
		return map[string]any{"k": "exact", "id": r.str()}
	case 376:
		return map[string]any{"k": "oneof", "ids": r.strs()}
	case 377:
		rel := r.str()
		return map[string]any{"k": "related", "rel": rel, "anchor": r.str()}
	}
	goalFail("bad resource part tag %d", k)
	return nil
}

func goalDRes(r *GoalTapeReader) map[string]any {
	k := r.k()
	switch k {
	case 370:
		return map[string]any{"k": "exact", "id": r.str()}
	case 371:
		return map[string]any{"k": "oneof", "ids": r.strs()}
	case 372:
		rel := r.str()
		return map[string]any{"k": "related", "rel": rel, "anchor": r.str()}
	case 373:
		return map[string]any{"k": "any", "reason": r.str()}
	case 374:
		return map[string]any{"k": "all_of", "parts": r.list(func() any { return goalDPart(r) })}
	}
	goalFail("bad resource selector tag %d", k)
	return nil
}

func goalExpect(r *GoalTapeReader, k int64, what string) {
	if r.k() != k {
		goalFail("%s expected", what)
	}
}

// goalDecodeGoal parses a goal tape; panics unless the whole tape is exactly one goal.
func goalDecodeGoal(t GoalTape) map[string]any {
	r := &GoalTapeReader{t: t}
	goalExpect(r, 480, "goal")
	v := r.int()
	principal := r.str()
	ontDigest := r.str()
	nlDigest := r.str()
	sources := r.strs()
	grant := func() any {
		goalExpect(r, 380, "grant")
		gid := r.str()
		verb := r.str()
		res := goalDRes(r)
		return map[string]any{"gid": gid, "verb": verb, "res": res, "cond": goalDCond(r)}
	}
	prohibit := func() any {
		goalExpect(r, 392, "prohibit")
		pid := r.str()
		var target map[string]any
		switch tk := r.k(); tk {
		case 390:
			target = map[string]any{"k": "verb", "verb": r.str()}
		case 391:
			target = map[string]any{"k": "effect", "cls": r.str()}
		default:
			goalFail("bad prohibit target")
		}
		res := goalDRes(r)
		return map[string]any{"pid": pid, "target": target, "res": res, "cond": goalDCond(r)}
	}
	bound := func() any {
		goalExpect(r, 451, "bound")
		bid := r.str()
		var sel map[string]any
		switch sk := r.k(); sk {
		case 410:
			sel = map[string]any{"k": "gids", "gids": r.strs()}
		case 411:
			sel = map[string]any{"k": "effect", "cls": r.str()}
		default:
			goalFail("bad selection")
		}
		goalExpect(r, 450, "bound core")
		agg := goalDAgg(r)
		value := goalDTerm(r)
		key := r.str()
		window := goalDWindow(r)
		scope := goalDScope(r)
		capQ := goalDQ(r)
		return map[string]any{"bid": bid, "sel": sel, "agg": agg, "value": value, "key": key, "window": window, "scope": scope, "cap": capQ,
			"onExceed": goalDOnExceed(r)}
	}
	hole := func() any {
		goalExpect(r, 470, "hole")
		hid := r.str()
		q := r.str()
		domain := r.strs()
		affects := r.strs()
		return map[string]any{"hid": hid, "q": q, "domain": domain, "affects": affects, "global": r.int() == 1}
	}
	grants := r.list(grant)
	prohibits := r.list(prohibit)
	bounds := r.list(bound)
	goalExpect(r, 460, "validity")
	nb := r.int()
	na := r.int()
	validity := map[string]any{"notBefore": goalNum(nb), "notAfter": goalNum(na), "maxIdle": goalNum(r.int())}
	goalExpect(r, 461, "delegation")
	md := r.int()
	nrw := r.int() == 1
	deleg := map[string]any{"maxDepth": goalNum(md), "narrowOnly": nrw, "mayTouch": r.strs()}
	escalateOn := r.list(func() any { return goalDCond(r) })
	wildcardAck := r.strs()
	holes := r.list(hole)
	if !r.done() {
		goalFail("trailing tokens after goal")
	}
	return map[string]any{"v": goalNum(v), "principal": principal, "ontDigest": ontDigest, "nlDigest": nlDigest, "sources": sources, "grants": grants,
		"prohibits": prohibits, "bounds": bounds, "validity": validity, "deleg": deleg, "escalateOn": escalateOn,
		"wildcardAck": wildcardAck, "holes": holes}
}

// GoalTapeFromJSON converts the reference's [["k", 480], ["s", "x"], ...] JSON form to a tape.
func goalTapeFromJSON(v any) GoalTape {
	l, ok := v.([]any)
	if !ok {
		goalFail("tape: array expected")
	}
	out := make(GoalTape, 0, len(l))
	for _, x := range l {
		p, ok := x.([]any)
		if !ok || len(p) != 2 {
			goalFail("malformed token")
		}
		tag, _ := p[0].(string)
		switch tag {
		case "k", "i":
			f, ok := jsNum(p[1])
			if !ok || f != math.Trunc(f) || math.Abs(f) > maxSafeInt {
				goalFail("malformed token")
			}
			out = append(out, GoalTok{Tag: tag[0], Int: int64(f)})
		case "s":
			s, ok := p[1].(string)
			if !ok {
				goalFail("malformed token")
			}
			out = append(out, GoalTok{Tag: 's', Str: s})
		default:
			goalFail("malformed token")
		}
	}
	return out
}

// GoalEncodeGoal, GoalEncodeOntology, GoalEncodeAct, GoalEncodeHist, GoalDecodeGoal and GoalDecodePolicy are the error-returning
// public forms of the codec.
func GoalEncodeGoal(g any) (t GoalTape, err error) {
	_, err = anlTry(func() any { t = goalEncodeGoal(g); return nil })
	return
}
func GoalEncodeOntology(o any) (t GoalTape, err error) {
	_, err = anlTry(func() any { t = goalEncodeOntology(o); return nil })
	return
}
func GoalEncodeAct(a any) (t GoalTape, err error) {
	_, err = anlTry(func() any { t = goalEncodeAct(a); return nil })
	return
}
func GoalEncodeHist(h any) (t GoalTape, err error) {
	_, err = anlTry(func() any { t = goalEncodeHist(h); return nil })
	return
}
func GoalDecodeGoal(t GoalTape) (g map[string]any, err error) {
	_, err = anlTry(func() any { g = goalDecodeGoal(t); return nil })
	return
}
func GoalDecodePolicy(t GoalTape) (p map[string]any, err error) {
	_, err = anlTry(func() any { p = goalDecodePolicy(t); return nil })
	return
}
