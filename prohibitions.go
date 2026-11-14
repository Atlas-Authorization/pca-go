package pca

// The prohibition language: the veto-polarity trigger (validate / match), the signed constitution, the monitor state and its
// hash chain, the monitor itself (check, advance), per-action safety evidence (unsigned and signed) and the composition rule
// (permissions grant, prohibitions veto). A port of the reference prohibitions module. Everything malformed, unknown or
// unresolvable fails closed; nothing here panics. Values are JSON as StrictParse produces them (map[string]any, []any, string,
// bool, nil, json.Number); the public entry points normalise their inputs, and results are the same shapes (maps and lists), so a
// result can be hashed or compared to a vector directly.

import (
	"encoding/json"
	"math"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const (
	ConstitutionVersion        = 1
	ConstitutionSigDomain      = "atlas-pca/constitution/v1\x00"
	EvidenceVersion            = 1
	SafetyEvidenceSigDomain    = "atlas-pca/safety-evidence/v1\x00"
	stateDigestDomain          = "atlas-pca/monitor-state/v1"
	stateChainDomain           = "atlas-pca/monitor-state-link/v1"
	MaxLedger                  = 10_000
	MaxInvariants              = 256
	MaxDeadline                = 1_000_000
	maxStateEntries            = 100_000
	maxStateKeys               = 1024
	maxIDLen                   = 128
	maxConditionDepth          = 32
	Unhashable                 = "<unhashable>"
	failClosedVerifyError      = "verification error (fail closed)"
	monitorEvalErrorReason     = "evaluation error (fail closed)"
	unsafeRegexResourceMessage = "unsafe regex resource"
)

var forbiddenIDs = []string{"__proto__", "constructor", "prototype"}

var conditionOps = []string{"eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists", "like", "matches", "is_a", "member_of"}

// ---- small JS-semantics helpers -------------------------------------------------------------------------------------

func pHas(o any, k string) bool {
	m, ok := o.(map[string]any)
	if !ok {
		return false
	}
	_, has := m[k]
	return has
}

func pFin(x any) bool {
	f, ok := jsNum(x)
	return ok && !math.IsInf(f, 0) && !math.IsNaN(f)
}

func pNum(x any) float64 { f, _ := jsNum(x); return f }

func pIsInteger(x any) bool { return pFin(x) && pNum(x) == math.Floor(pNum(x)) }

func pNegZero(x any) bool { f, ok := jsNum(x); return ok && f == 0 && math.Signbit(f) }

func pIsNum1(x any) bool { f, ok := jsNum(x); return ok && f == 1 }

func pStr(x any) (string, bool) { s, ok := x.(string); return s, ok }

func pNonEmptyStr(x any) bool { s, ok := x.(string); return ok && s != "" }

func pTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	}
	if f, ok := jsNum(v); ok {
		return f != 0 && !math.IsNaN(f)
	}
	return true
}

func isForbiddenID(k string) bool { return slices.Contains(forbiddenIDs, k) }

func pTextOf(m map[string]any, k string) string { return jsMemberString(m, k) }

func pSortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// jeq is JSON equality over normalised values (numbers by binary64 value).
func jeq(a, b any) bool {
	if fa, ok := jsNum(a); ok {
		fb, ok2 := jsNum(b)
		return ok2 && fa == fb
	}
	return reflect.DeepEqual(a, b)
}

// pNorm normalises a value into the strict-profile shapes; ok false when it cannot be.
func pNorm(v any) (any, bool) {
	n, err := NormalizeJSON(v)
	return n, err == nil
}

func copyObj(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func pOne() json.Number { return json.Number("1") }

func pInt(i int) json.Number { return json.Number(strconv.Itoa(i)) }

// ---- the veto-polarity trigger ---------------------------------------------------------------------------------------

// ValidateCondition is the structural problem of a condition ("" = well formed): a leaf, or an all_of / any_of / not grouping.
func ValidateCondition(c any, depth int) string {
	m, ok := c.(map[string]any)
	if !ok {
		return "condition not an object"
	}
	if depth > maxConditionDepth {
		return "condition nesting too deep"
	}
	if pHas(m, "all_of") || pHas(m, "any_of") || pHas(m, "not") {
		if pHas(m, "not") {
			return ValidateCondition(m["not"], depth+1)
		}
		key := "any_of"
		if pHas(m, "all_of") {
			key = "all_of"
		}
		arr, isList := m[key].([]any)
		if !isList || len(arr) == 0 {
			return "condition." + key + " must be a non-empty array"
		}
		for _, child := range arr {
			if e := ValidateCondition(child, depth+1); e != "" {
				return e
			}
		}
		return ""
	}
	if !pNonEmptyStr(m["field"]) {
		return "condition.field missing"
	}
	op, isStr := m["op"].(string)
	if !isStr || !slices.Contains(conditionOps, op) {
		return "unknown condition op " + jsMemberString(m, "op")
	}
	if pHas(m, "ref") && !pNonEmptyStr(m["ref"]) {
		return "bad condition.ref"
	}
	if op == "member_of" && pHas(m, "collection") && !pNonEmptyStr(m["collection"]) {
		return "bad condition.collection"
	}
	return ""
}

// ValidateWhen is the structural problem of a trigger ("" = well formed).
func ValidateWhen(w any, label string) string {
	m, ok := w.(map[string]any)
	if !ok {
		return label + ": not an object"
	}
	verbOK := false
	switch v := m["verb"].(type) {
	case string:
		verbOK = v != ""
	case []any:
		verbOK = len(v) > 0
		for _, x := range v {
			if !pNonEmptyStr(x) {
				verbOK = false
			}
		}
	}
	if !verbOK {
		return label + ": bad verb"
	}
	if r, has := m["resource"]; has {
		rs, isStr := r.(string)
		if !isStr {
			return label + ": bad resource"
		}
		if strings.HasPrefix(rs, "re:") {
			src := utf16Units(rs[3:])
			// an unsafe, over-long or uncompilable regex would make the matcher return false: the veto would silently NOT apply
			if len(src) > 200 || !isSafeRegexSource(src) {
				return label + ": " + unsafeRegexResourceMessage
			}
		}
	}
	if wh, has := m["where"]; has {
		list, isList := wh.([]any)
		if !isList {
			return label + ": where not an array"
		}
		for _, c := range list {
			if e := ValidateCondition(c, 0); e != "" {
				return label + ": " + e
			}
		}
	}
	return ""
}

// whenMatchesB is the VETO reading of a trigger, fully fail-closed: a malformed trigger, an unsafe or oversized regex, an unknown op,
// a missing field or operand, unavailable params or incomparable operands all count as MATCHED (the veto applies).
func whenMatchesB(w any, ctx any, b *regexBudget) (matched bool) {
	defer func() {
		if recover() != nil {
			matched = true
		}
	}()
	if ValidateWhen(w, "when") != "" {
		return true
	}
	wm := w.(map[string]any)
	cm, _ := ctx.(map[string]any)
	a, _ := cm["action"].(map[string]any)
	verb, vok := a["verb"].(string)
	res, rok := a["resource"].(string)
	_ = verb
	if !vok || !rok {
		return true
	}
	rs, _ := wm["resource"].(string)
	oversized := strings.HasPrefix(rs, "re:") && len(utf16Units(res)) > maxREResourceLen
	// an oversized subject for a regex resource: the matcher would say "no match", a veto must say "match"; a regex evaluation REFUSED
	// by the document budget is "could not decide", never "no match"
	refused0 := b.refusals
	trigger := map[string]any{"verb": wm["verb"]}
	if _, has := wm["resource"]; has && !oversized {
		trigger["resource"] = wm["resource"]
	}
	if !predicateMatches(trigger, cm, b) && b.refusals == refused0 {
		return false
	}
	where, _ := wm["where"].([]any)
	for _, c := range where {
		if evaluateConditionTri(c, cm, b) == triFalse {
			return false
		}
	}
	return true
}

// WhenMatches: does a prohibition trigger match, in the veto reading. Never panics.
func WhenMatches(w any, ctx any) bool {
	wn, _ := pNorm(w)
	cn, _ := pNorm(ctx)
	return whenMatchesB(wn, cn, &regexBudget{})
}

func whenAffirmativeB(w any, ctx any, b *regexBudget) (m bool) {
	defer func() {
		if recover() != nil {
			m = false
		}
	}()
	cm, _ := ctx.(map[string]any)
	return ValidateWhen(w, "when") == "" && predicateMatches(w, cm, b)
}

// WhenAffirmative is the plain permission reading: anything that cannot be decided is not matched.
func WhenAffirmative(w any, ctx any) bool {
	wn, _ := pNorm(w)
	cn, _ := pNorm(ctx)
	return whenAffirmativeB(wn, cn, &regexBudget{})
}

// ---- the constitution ------------------------------------------------------------------------------------------------

func constitutionBody(c map[string]any) map[string]any {
	out := make(map[string]any, len(c))
	for k, v := range c {
		if k != "id" && k != "sig" {
			out[k] = v
		}
	}
	return out
}

func pDomainMessage(domain, id string) []byte { return append([]byte(domain), sha([]byte(id))...) }

// ConstitutionID is the content address of a constitution body.
func ConstitutionID(c any) (string, error) {
	n, _ := pNorm(c)
	m, ok := n.(map[string]any)
	if !ok {
		return "", errMalformed
	}
	return HashCanonical(constitutionBody(m))
}

type pError string

func (e pError) Error() string { return string(e) }

const errMalformed = pError("malformed input")

// SignConstitution signs a well-formed constitution with the principal's Ed25519 seed (the principal key is c.principal).
func SignConstitution(c any, principalSeed []byte) (map[string]any, error) {
	n, _ := pNorm(c)
	if problems := ValidateConstitution(n); len(problems) > 0 {
		return nil, pError("signConstitution: " + strings.Join(problems, "; "))
	}
	m := n.(map[string]any)
	id, err := HashCanonical(constitutionBody(m))
	if err != nil {
		return nil, err
	}
	kp, err := KeyPairFromSeed(principalSeed)
	if err != nil {
		return nil, err
	}
	out := constitutionBody(m)
	out["id"] = id
	out["sig"] = b64.EncodeToString(kp.Sign(pDomainMessage(ConstitutionSigDomain, id)))
	return out, nil
}

// VerifyConstitution: well formed, id matches the content, signature by expectedPrincipal ("" = the embedded principal). Never panics.
func VerifyConstitution(sc any, expectedPrincipal string) (res map[string]any) {
	defer func() {
		if recover() != nil {
			res = map[string]any{"ok": false, "reason": failClosedVerifyError}
		}
	}()
	n, _ := pNorm(sc)
	if problems := ValidateConstitution(n); len(problems) > 0 {
		return map[string]any{"ok": false, "reason": problems[0]}
	}
	m := n.(map[string]any)
	if expectedPrincipal != "" && m["principal"] != any(expectedPrincipal) {
		return map[string]any{"ok": false, "reason": "principal mismatch"}
	}
	id, err := HashCanonical(constitutionBody(m))
	if idv, isStr := m["id"].(string); !isStr || err != nil || idv != id {
		return map[string]any{"ok": false, "reason": "id does not match content"}
	}
	sig, isStr := m["sig"].(string)
	if !isStr || !verifyB64u(m["principal"].(string), pDomainMessage(ConstitutionSigDomain, id), sig) {
		return map[string]any{"ok": false, "reason": "bad signature"}
	}
	return map[string]any{"ok": true}
}

func validateConditions(cs any, label string) string {
	list, ok := cs.([]any)
	if !ok || len(list) == 0 {
		return label + " must be a non-empty array"
	}
	for _, c := range list {
		if e := ValidateCondition(c, 0); e != "" {
			return e
		}
	}
	return ""
}

func isActionPath(v any) bool { s, ok := v.(string); return ok && strings.HasPrefix(s, "action.") }

// ValidateInvariant: the structural problems with an invariant (empty = well formed).
func ValidateInvariant(inv any) []string {
	m, ok := inv.(map[string]any)
	if !ok {
		return []string{"invariant not an object"}
	}
	id, isStr := m["id"].(string)
	if !isStr || id == "" {
		return []string{"<no id>: missing id"}
	}
	err := func(msg string) []string { return []string{id + ": " + msg} }
	if len(utf16Units(id)) > maxIDLen {
		return err("id too long")
	}
	if isForbiddenID(id) {
		return err("forbidden id")
	}
	kind, _ := m["kind"].(string)
	first := func(es ...string) []string {
		for _, e := range es {
			if e != "" {
				return err(e)
			}
		}
		return nil
	}
	switch kind {
	case "never":
		return first(ValidateWhen(m["when"], "when"))
	case "never_unless":
		if e := ValidateWhen(m["when"], "when"); e != "" {
			return err(e)
		}
		return first(validateConditions(m["unless"], "unless"))
	case "cap":
		if e := ValidateWhen(m["when"], "when"); e != "" {
			return err(e)
		}
		if !isActionPath(m["amount"]) {
			return err("amount must be an action.* path")
		}
		if !pFin(m["max"]) || pNum(m["max"]) < 0 {
			return err("max must be a finite number >= 0")
		}
		if ws, has := m["window_secs"]; has && (!pFin(ws) || pNum(ws) <= 0) {
			return err("bad window_secs")
		}
		return nil
	case "rate":
		if e := ValidateWhen(m["when"], "when"); e != "" {
			return err(e)
		}
		if mx := m["max"]; !pIsInteger(mx) || pNum(mx) < 0 || pNegZero(mx) || pNum(mx) > MaxLedger {
			return err("max must be an integer in [0,10000]")
		}
		if !pFin(m["window_secs"]) || pNum(m["window_secs"]) <= 0 {
			return err("window_secs must be > 0")
		}
		return nil
	case "never_after":
		e := ValidateWhen(m["after"], "after")
		if e == "" {
			e = ValidateWhen(m["forbid"], "forbid")
		}
		return first(e)
	case "require_prior":
		e := ValidateWhen(m["when"], "when")
		if e == "" {
			e = ValidateWhen(m["prior"], "prior")
		}
		return first(e)
	case "require_approval_over":
		if e := ValidateWhen(m["when"], "when"); e != "" {
			return err(e)
		}
		if !isActionPath(m["amount"]) {
			return err("amount must be an action.* path")
		}
		if !pFin(m["threshold"]) || pNum(m["threshold"]) < 0 {
			return err("threshold must be a finite number >= 0")
		}
		return first(validateConditions(m["approved"], "approved"))
	}
	return err("unknown invariant kind " + pTextOf(m, "kind"))
}

// ValidateConstitution: the structural problems with a constitution (empty = well formed).
func ValidateConstitution(c any) []string {
	m, ok := c.(map[string]any)
	if !ok {
		return []string{"constitution not an object"}
	}
	out := []string{}
	if !pIsNum1(m["version"]) {
		out = append(out, "unsupported version "+pTextOf(m, "version"))
	}
	if !pNonEmptyStr(m["principal"]) {
		out = append(out, "principal missing")
	}
	invs, isList := m["invariants"].([]any)
	if !isList {
		return append(out, "invariants not an array")
	}
	if len(invs) > MaxInvariants {
		out = append(out, "too many invariants")
	}
	seen := map[string]bool{}
	for _, inv := range invs {
		out = append(out, ValidateInvariant(inv)...)
		if im, isObj := inv.(map[string]any); isObj {
			if id, isStr := im["id"].(string); isStr {
				if seen[id] {
					out = append(out, id+": duplicate id")
				}
				seen[id] = true
			}
		}
	}
	return out
}

// ---- canonical monitor state -----------------------------------------------------------------------------------------

// EmptyMonitorState is the genesis monitor state at time now: empty ledger, no latches, seq 0, no parent.
func EmptyMonitorState(now any) map[string]any {
	return map[string]any{"now": now, "seq": pInt(0), "parent": nil, "ledger": map[string]any{}, "latched": map[string]any{}}
}

func badStateKey(k string) bool { return isForbiddenID(k) || len(utf16Units(k)) > maxIDLen }

// StateProblem is the structural problem with a monitor state ("" = well formed). Total.
func StateProblem(state any) (problem string) {
	const bad = "malformed monitor state"
	defer func() {
		if recover() != nil {
			problem = bad
		}
	}()
	s, ok := state.(map[string]any)
	if !ok || !pFin(s["now"]) {
		return bad
	}
	ledger, ok1 := s["ledger"].(map[string]any)
	latched, ok2 := s["latched"].(map[string]any)
	if !ok1 || !ok2 {
		return bad
	}
	if seq := s["seq"]; !pIsInteger(seq) || pNum(seq) < 0 || pNegZero(seq) {
		return bad + ": seq"
	}
	parent, hasParent := s["parent"]
	if !hasParent || (parent != nil && !isString(parent)) {
		return bad + ": parent"
	}
	seq := pNum(s["seq"])
	if seq == 0 && parent != nil {
		return bad + ": genesis has a parent"
	}
	if seq > 0 && parent == nil {
		return bad + ": missing chain link"
	}
	now := pNum(s["now"])
	if len(ledger) > maxStateKeys || len(latched) > maxStateKeys {
		return bad + ": too many keys"
	}
	total := 0
	for _, k := range pSortedKeys(ledger) {
		if badStateKey(k) {
			return bad + ": bad ledger key"
		}
		l, isList := ledger[k].([]any)
		if !isList || len(l) > MaxLedger {
			return bad + ": bad ledger"
		}
		total += len(l)
		for _, ev := range l {
			e, isObj := ev.(map[string]any)
			if !isObj || !pFin(e["t"]) || !pFin(e["amount"]) || pNum(e["amount"]) < 0 {
				return bad + ": bad ledger entry"
			}
			// an entry from the "future" would be ignored by the window and so UNDER-count: refuse (clock regression)
			if pNum(e["t"]) > now {
				return bad + ": ledger entry after now (clock regression)"
			}
		}
	}
	if total > maxStateEntries {
		return bad + ": too many entries"
	}
	for _, k := range pSortedKeys(latched) {
		if badStateKey(k) {
			return bad + ": bad latch key"
		}
		if t := latched[k]; !pFin(t) || pNum(t) > now {
			return bad + ": bad latch"
		}
	}
	if dlv, has := s["deadlines"]; has {
		dl, isObj := dlv.(map[string]any)
		if !isObj {
			return bad + ": deadlines"
		}
		if len(dl) > maxStateKeys {
			return bad + ": too many deadline keys"
		}
		for _, k := range pSortedKeys(dl) {
			if badStateKey(k) {
				return bad + ": bad deadline key"
			}
			if d := dl[k]; !pIsInteger(d) || pNum(d) < 1 || pNum(d) > MaxDeadline {
				return bad + ": bad deadline"
			}
		}
	}
	return ""
}

func isString(v any) bool { _, ok := v.(string); return ok }

func sortEntries(es []any) {
	sort.SliceStable(es, func(i, j int) bool {
		a, b := es[i].(map[string]any), es[j].(map[string]any)
		if pNum(a["t"]) != pNum(b["t"]) {
			return pNum(a["t"]) < pNum(b["t"])
		}
		return pNum(a["amount"]) < pNum(b["amount"])
	})
}

// canonicalState: unknown fields dropped, ledger entries reduced to {t, amount} and sorted, empty ledger arrays omitted. ok false on a
// malformed state.
func canonicalState(state any) (map[string]any, bool) {
	if StateProblem(state) != "" {
		return nil, false
	}
	s := state.(map[string]any)
	ledger := map[string]any{}
	for k, v := range s["ledger"].(map[string]any) {
		var l []any
		for _, ev := range v.([]any) {
			e := ev.(map[string]any)
			l = append(l, map[string]any{"t": e["t"], "amount": e["amount"]})
		}
		sortEntries(l)
		if len(l) > 0 {
			ledger[k] = l
		}
	}
	base := map[string]any{"d": stateDigestDomain, "now": s["now"], "seq": s["seq"], "parent": s["parent"], "ledger": ledger,
		"latched": copyObj(s["latched"].(map[string]any))}
	if dl, has := s["deadlines"]; has {
		if d := copyObj(dl.(map[string]any)); len(d) > 0 {
			base["deadlines"] = d
		}
	}
	return base, true
}

// StateDigest is the digest of the canonical form of a state.
func StateDigest(state any) (string, error) {
	n, _ := pNorm(state)
	c, ok := canonicalState(n)
	if !ok {
		return "", pError(StateProblem(n))
	}
	return HashCanonical(c)
}

// TickState is the same state at a later now; it refuses regression. Never panics.
func TickState(state any, now any) map[string]any {
	n, _ := pNorm(state)
	nn, _ := pNorm(now)
	if StateProblem(n) != "" {
		return map[string]any{"ok": false, "reason": "malformed monitor state"}
	}
	s := n.(map[string]any)
	if !pFin(nn) || pNum(nn) < pNum(s["now"]) {
		return map[string]any{"ok": false, "reason": "clock regression"}
	}
	out := copyObj(s)
	out["now"] = nn
	return map[string]any{"ok": true, "state": out}
}

// ---- the monitor -----------------------------------------------------------------------------------------------------

func allHold(cs any, ctx map[string]any, b *regexBudget) bool {
	list, _ := cs.([]any)
	for _, c := range list {
		if evaluateConditionTri(c, ctx, b) != triTrue {
			return false
		}
	}
	return true
}

func windowEntries(state map[string]any, id string, inv map[string]any) []any {
	l, isList := state["ledger"].(map[string]any)[id].([]any)
	if !isList {
		return nil
	}
	lo := math.Inf(-1)
	if ws, has := inv["window_secs"]; has && ws != nil {
		lo = pNum(state["now"]) - pNum(ws)*1000
	}
	now := pNum(state["now"])
	var out []any
	for _, ev := range l {
		e := ev.(map[string]any)
		if pNum(e["t"]) > lo && pNum(e["t"]) <= now {
			out = append(out, e)
		}
	}
	sortEntries(out)
	return out
}

func invReason(inv map[string]any, def string) any {
	if d, has := inv["description"]; has && d != nil {
		return d
	}
	return def
}

type invResult struct {
	ok     bool
	reason any
}

func evalOne(inv map[string]any, ctx map[string]any, state map[string]any, b *regexBudget) invResult {
	kind, _ := inv["kind"].(string)
	id := inv["id"].(string)
	pass := invResult{ok: true}
	switch kind {
	case "never":
		if whenMatchesB(inv["when"], ctx, b) {
			return invResult{false, invReason(inv, "forbidden action")}
		}
		return pass
	case "never_unless":
		if !whenMatchesB(inv["when"], ctx, b) {
			return pass
		}
		// exceptions must hold AFFIRMATIVELY (unresolvable => false => still forbidden)
		if allHold(inv["unless"], ctx, b) {
			return pass
		}
		return invResult{false, invReason(inv, "forbidden without required condition")}
	case "cap":
		if !whenMatchesB(inv["when"], ctx, b) {
			return pass
		}
		a, found := resolvePath(ctx, inv["amount"])
		if !found || !pFin(a) || pNum(a) < 0 {
			return invResult{false, "amount unresolvable (fail closed)"}
		}
		spent := 0.0
		for _, e := range windowEntries(state, id, inv) {
			spent += pNum(e.(map[string]any)["amount"])
		}
		if spent+pNum(a) <= pNum(inv["max"]) {
			return pass
		}
		return invResult{false, "cap exceeded: " + jsValueString(jsNumber(spent)) + " + " + jsValueString(a) + " > " + jsValueString(inv["max"])}
	case "rate":
		if !whenMatchesB(inv["when"], ctx, b) {
			return pass
		}
		n := len(windowEntries(state, id, inv))
		if float64(n+1) <= pNum(inv["max"]) {
			return pass
		}
		return invResult{false, "rate exceeded: " + strconv.Itoa(n+1) + " > " + jsValueString(inv["max"]) + " per " + jsValueString(inv["window_secs"]) + "s"}
	case "never_after":
		if _, latched := state["latched"].(map[string]any)[id]; !latched || !whenMatchesB(inv["forbid"], ctx, b) {
			return pass
		}
		return invResult{false, invReason(inv, "forbidden after trigger")}
	case "require_prior":
		if !whenMatchesB(inv["when"], ctx, b) {
			return pass
		}
		if _, latched := state["latched"].(map[string]any)[id]; latched {
			return pass
		}
		return invResult{false, invReason(inv, "required prior action not admitted")}
	case "require_approval_over":
		if !whenMatchesB(inv["when"], ctx, b) {
			return pass
		}
		a, found := resolvePath(ctx, inv["amount"])
		over := !found || !pFin(a) || pNum(a) < 0 || pNum(a) > pNum(inv["threshold"])
		if !over || allHold(inv["approved"], ctx, b) {
			return pass
		}
		return invResult{false, invReason(inv, "approval required over "+jsValueString(inv["threshold"]))}
	}
	panic("unknown invariant kind") // unreachable after validation; the caller turns it into a fail-closed row
}

func actionOK(action any) bool {
	m, _ := action.(map[string]any)
	a, _ := m["action"].(map[string]any)
	return isString(a["verb"]) && isString(a["resource"])
}

// CheckProhibitions evaluates EVERY invariant (no short-circuit) against the action and the running state. Pure, total, fail-closed.
func CheckProhibitions(action, constitution, state any) map[string]any {
	a, _ := pNorm(action)
	c, _ := pNorm(constitution)
	s, _ := pNorm(state)
	return checkProhibitionsB(a, c, s, &regexBudget{})
}

func checkProhibitionsB(action, constitution, state any, b *regexBudget) (res map[string]any) {
	fail := func(id, reason string) map[string]any {
		return map[string]any{"ok": false, "violated": []any{id}, "reasons": []any{reason},
			"evaluated": []any{map[string]any{"id": id, "kind": "structural", "result": "violated", "reason": reason}}}
	}
	defer func() {
		if recover() != nil {
			res = fail("<monitor>", "monitor error (fail closed)")
		}
	}()
	if cp := ValidateConstitution(constitution); len(cp) > 0 {
		return fail("<constitution>", cp[0])
	}
	if !actionOK(action) {
		return fail("<action>", "malformed action")
	}
	if sp := StateProblem(state); sp != "" {
		return fail("<state>", sp)
	}
	evaluated := []any{}
	for _, iv := range constitution.(map[string]any)["invariants"].([]any) {
		inv := iv.(map[string]any)
		r := func() (r invResult) {
			defer func() {
				if recover() != nil {
					r = invResult{false, monitorEvalErrorReason}
				}
			}()
			return evalOne(inv, action.(map[string]any), state.(map[string]any), b)
		}()
		row := map[string]any{"id": inv["id"], "kind": inv["kind"], "result": "violated"}
		if r.ok {
			row["result"] = "pass"
		}
		if pTruthy(r.reason) {
			row["reason"] = r.reason
		}
		evaluated = append(evaluated, row)
	}
	violated, reasons := []any{}, []any{}
	for _, ev := range evaluated {
		e := ev.(map[string]any)
		if e["result"] == "violated" {
			violated = append(violated, e["id"])
			why := "violated"
			if r, has := e["reason"]; has {
				why = jsValueString(r)
			}
			reasons = append(reasons, jsValueString(e["id"])+": "+why)
		}
	}
	return map[string]any{"ok": len(violated) == 0, "violated": violated, "reasons": reasons, "evaluated": evaluated}
}

// AdvanceStateStrict is the pure state transition for an ADMITTED action, at the state's own now. {ok:false, reason} on anything it
// cannot record faithfully. Never panics.
func AdvanceStateStrict(action, constitution, state any) map[string]any {
	s, _ := pNorm(state)
	var now any
	if sm, ok := s.(map[string]any); ok {
		now = sm["now"]
	}
	return advanceStateStrictAt(action, constitution, s, now)
}

// AdvanceStateStrictAt is AdvanceStateStrict at an explicit now (nil = not a finite number: a clock regression).
func AdvanceStateStrictAt(action, constitution, state, now any) map[string]any {
	s, _ := pNorm(state)
	n, _ := pNorm(now)
	return advanceStateStrictAt(action, constitution, s, n)
}

func advanceStateStrictAt(action, constitution, state, now any) map[string]any {
	a, _ := pNorm(action)
	c, _ := pNorm(constitution)
	return advanceInner(a, c, state, now, &regexBudget{})
}

func advanceInner(action, constitution, state, now any, b *regexBudget) (res map[string]any) {
	no := func(reason string) map[string]any { return map[string]any{"ok": false, "reason": reason} }
	defer func() {
		if recover() != nil {
			res = no("advance error (fail closed)")
		}
	}()
	if cp := ValidateConstitution(constitution); len(cp) > 0 {
		return no(cp[0])
	}
	if sp := StateProblem(state); sp != "" {
		return no(sp)
	}
	st := state.(map[string]any)
	if !pFin(now) || pNum(now) < pNum(st["now"]) {
		return no("clock regression")
	}
	if !actionOK(action) {
		return no("malformed action")
	}
	canon, _ := canonicalState(state)
	prevDigest, err := HashCanonical(canon)
	if err != nil {
		return no("advance error (fail closed)")
	}
	actionDigest, err := HashCanonical(action)
	if err != nil {
		return no("advance error (fail closed)")
	}
	ledger := map[string]any{}
	for k, v := range canon["ledger"].(map[string]any) {
		ledger[k] = slices.Clone(v.([]any))
	}
	latched := copyObj(canon["latched"].(map[string]any))
	am := action.(map[string]any)
	nowF := pNum(now)
	for _, iv := range constitution.(map[string]any)["invariants"].([]any) {
		inv := iv.(map[string]any)
		id := inv["id"].(string)
		switch inv["kind"] {
		case "cap", "rate":
			prev, _ := ledger[id].([]any)
			lo := math.Inf(-1)
			if ws, has := inv["window_secs"]; has && ws != nil {
				lo = nowF - pNum(ws)*1000
			}
			kept := []any{}
			for _, ev := range prev {
				if pNum(ev.(map[string]any)["t"]) > lo {
					kept = append(kept, ev)
				}
			}
			if whenMatchesB(inv["when"], am, b) {
				var amount any = pOne()
				if inv["kind"] == "cap" {
					v, found := resolvePath(am, inv["amount"])
					if !found || !pFin(v) || pNum(v) < 0 {
						return no(id + ": amount unresolvable")
					}
					amount = v
				}
				kept = append(kept, map[string]any{"t": now, "amount": amount})
			}
			sortEntries(kept)
			if len(kept) > MaxLedger {
				if inv["kind"] == "rate" {
					return no(id + ": rate ledger overflow")
				}
				for len(kept) > MaxLedger {
					x, y := kept[0].(map[string]any), kept[1].(map[string]any) // merge the oldest two; keeps the LATER time => never under-counts a cap
					merged := map[string]any{"t": y["t"], "amount": jsNumber(pNum(x["amount"]) + pNum(y["amount"]))}
					kept = append([]any{merged}, kept[2:]...)
				}
			}
			if len(kept) > 0 {
				ledger[id] = kept
			} else {
				delete(ledger, id)
			}
		case "never_after":
			// conservative match: an ambiguous trigger latches (stricter)
			if _, done := latched[id]; !done && whenMatchesB(inv["after"], am, b) {
				latched[id] = now
			}
		case "require_prior":
			// AFFIRMATIVE match: an ambiguous prerequisite must NOT count as satisfied
			if _, done := latched[id]; !done && whenAffirmativeB(inv["prior"], am, b) {
				latched[id] = now
			}
		}
	}
	parent, err := HashCanonical(map[string]any{"d": stateChainDomain, "state": prevDigest, "action": actionDigest})
	if err != nil {
		return no("advance error (fail closed)")
	}
	nxt := map[string]any{"now": now, "seq": jsNumber(pNum(st["seq"]) + 1), "parent": parent, "ledger": ledger, "latched": latched}
	if StateProblem(nxt) != "" {
		return no("resulting state invalid")
	}
	return map[string]any{"ok": true, "state": nxt}
}

// AdvanceState is AdvanceStateStrict that returns the INPUT state unchanged on failure.
func AdvanceState(action, constitution, state any) any {
	r := AdvanceStateStrict(action, constitution, state)
	if r["ok"] == true {
		return r["state"]
	}
	return state
}

// ---- per-action safety evidence --------------------------------------------------------------------------------------

func safeStr(f func() (string, error)) string {
	s, err := func() (s string, err error) {
		defer func() {
			if recover() != nil {
				err = errMalformed
			}
		}()
		return f()
	}()
	if err != nil {
		return Unhashable
	}
	return s
}

// ProveSafety builds the evidence a verifier re-checks. Never panics.
func ProveSafety(action, constitution, state any) map[string]any {
	a, _ := pNorm(action)
	c, _ := pNorm(constitution)
	s, _ := pNorm(state)
	return evidenceFrom(checkProhibitionsB(a, c, s, &regexBudget{}), a, c, s)
}

func evidenceFrom(r map[string]any, action, constitution, state any) map[string]any {
	cid := safeStr(func() (string, error) { return ConstitutionID(constitution) })
	adg := safeStr(func() (string, error) { return HashCanonical(action) })
	sdg := safeStr(func() (string, error) { return StateDigest(state) })
	extra := []string{}
	if cid == Unhashable {
		extra = append(extra, "<constitution>")
	}
	if adg == Unhashable {
		extra = append(extra, "<action>")
	}
	if sdg == Unhashable {
		extra = append(extra, "<state>")
	}
	var now any = pInt(0)
	if sm, ok := state.(map[string]any); ok && pFin(sm["now"]) {
		now = sm["now"]
	}
	evaluated := []any{}
	for _, e := range r["evaluated"].([]any) {
		evaluated = append(evaluated, copyObj(e.(map[string]any)))
	}
	violated := slices.Clone(r["violated"].([]any))
	for _, x := range extra {
		if !slices.Contains(violated, any(x)) {
			violated = append(violated, x)
		}
	}
	return map[string]any{"v": pInt(EvidenceVersion), "constitution": cid, "action_digest": adg, "state_digest": sdg, "now": now,
		"evaluated": evaluated, "ok": r["ok"] == true && len(extra) == 0, "violated": violated}
}

// EvidenceDigest is the digest of an evidence object.
func EvidenceDigest(e any) (string, error) { return HashCanonical(e) }

// VerifySafetyEvidence recomputes the monitor and requires the evidence to match EXACTLY. Never panics.
func VerifySafetyEvidence(evidence, action, constitution, state any) (res map[string]any) {
	no := func(reason string) map[string]any { return map[string]any{"ok": false, "reason": reason} }
	defer func() {
		if recover() != nil {
			res = no(failClosedVerifyError)
		}
	}()
	ev, _ := pNorm(evidence)
	em, isObj := ev.(map[string]any)
	if !isObj || !pIsNum1(em["v"]) {
		return no("unsupported evidence version")
	}
	fresh := ProveSafety(action, constitution, state)
	if fresh["constitution"] != em["constitution"] {
		return no("constitution mismatch")
	}
	if fresh["action_digest"] != em["action_digest"] {
		return no("action digest mismatch")
	}
	if fresh["state_digest"] != em["state_digest"] {
		return no("state digest mismatch")
	}
	h1, e1 := HashCanonical(fresh)
	h2, e2 := HashCanonical(em)
	if e1 != nil || e2 != nil {
		return no(failClosedVerifyError)
	}
	if h1 != h2 {
		return no("evidence does not reproduce")
	}
	if fresh["ok"] != true {
		return no("prohibition violated: " + joinAny(fresh["violated"].([]any)))
	}
	return map[string]any{"ok": true}
}

func joinAny(xs []any) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = jsValueString(x)
	}
	return strings.Join(parts, ",")
}

// SafetyBindingID is the id a signed evidence binds: the evidence, its three digests and the signer.
func SafetyBindingID(evidence map[string]any, signer string) (string, error) {
	for _, k := range []string{"action_digest", "constitution", "state_digest"} {
		if _, has := evidence[k]; !has { // the reference canonicalizer refuses an undefined member
			return "", pError("safetyBindingId: missing " + k)
		}
	}
	eh, err := HashCanonical(evidence)
	if err != nil {
		return "", err
	}
	return HashCanonical(map[string]any{"d": SafetyEvidenceSigDomain, "signer": signer, "evidence": eh, "constitution": evidence["constitution"],
		"action_digest": evidence["action_digest"], "state_digest": evidence["state_digest"]})
}

// SignSafetyEvidence signs evidence (bound to its constitution, action and state digests) with the signer's Ed25519 seed.
func SignSafetyEvidence(evidence any, signerSeed []byte, signerPublic string) (map[string]any, error) {
	n, _ := pNorm(evidence)
	em, isObj := n.(map[string]any)
	if !isObj || !pIsNum1(em["v"]) {
		return nil, pError("signSafetyEvidence: unsupported evidence")
	}
	for _, k := range []string{"constitution", "action_digest", "state_digest"} {
		if d, ok := em[k].(string); !ok || d == "" || d == Unhashable {
			return nil, pError("signSafetyEvidence: unbound evidence")
		}
	}
	if signerPublic == "" {
		return nil, pError("signSafetyEvidence: signer missing")
	}
	id, err := SafetyBindingID(em, signerPublic)
	if err != nil {
		return nil, err
	}
	kp, err := KeyPairFromSeed(signerSeed)
	if err != nil {
		return nil, err
	}
	return map[string]any{"evidence": em, "signer": signerPublic, "id": id, "sig": b64.EncodeToString(kp.Sign(pDomainMessage(SafetyEvidenceSigDomain, id)))}, nil
}

// propOf is JS `o.k`: undefined (nil here) on a non-object, a TypeError (panic, caught by the caller) on null.
func propOf(o any, k string) any {
	if o == nil {
		panic("cannot read properties of null")
	}
	m, _ := o.(map[string]any)
	return m[k]
}

// VerifySignedSafetyEvidence verifies signed evidence offline: signer pinned, binding id, signature, bound digests, internal
// consistency and (when all three are given) a full recomputation. expected carries signer (string or list), action | actionDigest,
// constitution | constitutionId, state | stateDigest, optional principal and requireOk.
func VerifySignedSafetyEvidence(signed, expected any) (res map[string]any) {
	no := func(reason string) map[string]any { return map[string]any{"ok": false, "reason": reason} }
	defer func() {
		if recover() != nil {
			res = no(failClosedVerifyError)
		}
	}()
	sn, _ := pNorm(signed)
	xn, _ := pNorm(expected)
	sm, ok1 := sn.(map[string]any)
	exp, ok3 := xn.(map[string]any)
	if !ok1 || !ok3 {
		return no("malformed input")
	}
	ev, ok2 := sm["evidence"].(map[string]any)
	if !ok2 {
		return no("malformed input")
	}
	if !pIsNum1(ev["v"]) {
		return no("unsupported evidence version")
	}
	signers, isList := exp["signer"].([]any)
	if !isList {
		signers = []any{exp["signer"]}
	}
	if len(signers) == 0 {
		return no("no pinned signer")
	}
	for _, s := range signers {
		if !pNonEmptyStr(s) {
			return no("no pinned signer")
		}
	}
	signer, isStr := sm["signer"].(string)
	if !isStr || !slices.Contains(signers, any(signer)) {
		return no("signer not trusted")
	}
	if !pHas(exp, "action") && !pHas(exp, "actionDigest") {
		return no("unbound: action not specified")
	}
	if !pHas(exp, "constitution") && !pHas(exp, "constitutionId") {
		return no("unbound: constitution not specified")
	}
	if !pHas(exp, "state") && !pHas(exp, "stateDigest") {
		return no("unbound: state not specified")
	}
	bid, err := SafetyBindingID(ev, signer)
	if err != nil && isString(sm["id"]) { // the reference throws on unhashable evidence (after its id type test): fail closed
		panic(err)
	}
	if id, isStr := sm["id"].(string); !isStr || id != bid {
		return no("binding id mismatch")
	}
	if sig, isStr := sm["sig"].(string); !isStr || !verifyB64u(signer, pDomainMessage(SafetyEvidenceSigDomain, bid), sig) {
		return no("bad signature")
	}

	var wantAction any = exp["actionDigest"]
	if pHas(exp, "action") {
		h, err := HashCanonical(exp["action"])
		if err != nil {
			panic(err)
		}
		wantAction = h
		if pHas(exp, "actionDigest") && exp["actionDigest"] != any(h) {
			return no("expected action and digest disagree")
		}
	}
	if ev["action_digest"] != wantAction {
		return no("action digest mismatch (evidence bound to another action)")
	}

	if pHas(exp, "principal") {
		sc, isObj := exp["constitution"].(map[string]any)
		if !isObj || !isString(sc["sig"]) {
			return no("principal pin requires a signed constitution")
		}
		principal, isStr := exp["principal"].(string)
		if !isStr || principal == "" {
			principal = "\x00" // never equal to a constitution's principal: VerifyConstitution reports the mismatch
		}
		vc := VerifyConstitution(sc, principal)
		if vc["ok"] != true {
			r, has := vc["reason"]
			if !has {
				r = "undefined"
			}
			return no("constitution not authentic: " + jsValueString(r))
		}
	}
	var wantConst any = exp["constitutionId"]
	if pHas(exp, "constitution") {
		h, err := ConstitutionID(exp["constitution"])
		if err != nil {
			panic(err)
		}
		wantConst = h
		if pHas(exp, "constitutionId") && exp["constitutionId"] != any(h) {
			return no("expected constitution and id disagree")
		}
	}
	if ev["constitution"] != wantConst {
		return no("constitution mismatch (evidence bound to another constitution)")
	}

	// a malformed expected constitution never verifies: an invariant without a string id would otherwise "cover" an id-less row
	if pHas(exp, "constitution") {
		if cp := ValidateConstitution(exp["constitution"]); len(cp) > 0 {
			return no("constitution malformed: " + cp[0])
		}
	}

	var wantState any = exp["stateDigest"]
	if pHas(exp, "state") {
		h, err := StateDigest(exp["state"])
		if err != nil {
			panic(err)
		}
		wantState = h
		if pHas(exp, "stateDigest") && exp["stateDigest"] != any(h) {
			return no("expected state and digest disagree")
		}
	}
	if ev["state_digest"] != wantState {
		return no("state digest mismatch (evidence bound to another state)")
	}

	evaluated, e1 := ev["evaluated"].([]any)
	violated, e2 := ev["violated"].([]any)
	if !e1 || !e2 {
		return no("malformed evidence")
	}
	for _, r := range evaluated {
		if rm, isObj := r.(map[string]any); isObj && pHas(rm, "id") && !isString(rm["id"]) {
			return no("malformed evidence")
		}
	}
	badRows := 0
	for _, r := range evaluated {
		if rm, isObj := r.(map[string]any); !isObj || rm["result"] != "pass" {
			badRows++
		}
	}
	evOK, isBool := ev["ok"].(bool)
	if !isBool || evOK != (badRows == 0 && len(violated) == 0) {
		return no("evidence verdict inconsistent with rows")
	}

	if pHas(exp, "action") && pHas(exp, "constitution") && pHas(exp, "state") {
		full := VerifySafetyEvidence(ev, exp["action"], exp["constitution"], exp["state"])
		reason, hasReason := full["reason"].(string)
		if full["ok"] != true && evOK {
			if !hasReason || reason == "" {
				reason = "evidence does not reproduce"
			}
			return no(reason)
		}
		if full["ok"] != true && !evOK && hasReason && !strings.HasPrefix(reason, "prohibition violated") {
			return no(reason)
		}
	} else if evOK && pHas(exp, "constitution") {
		invs := propOf(exp["constitution"], "invariants")
		list, isList := invs.([]any)
		if !isList {
			panic("not iterable")
		}
		ids := make([]any, len(list))
		for i, iv := range list {
			ids[i] = propOf(iv, "id")
		}
		if len(evaluated) != len(ids) {
			return no("evidence does not cover every invariant")
		}
		for i, r := range evaluated {
			var rid any // JS `r?.id`: undefined for a null or non-object row
			if rm, isObj := r.(map[string]any); isObj {
				rid = rm["id"]
			}
			if !jeq(rid, ids[i]) {
				return no("evidence does not cover every invariant")
			}
		}
	}
	if exp["requireOk"] != false && !evOK {
		return no("prohibition violated: " + joinAny(violated))
	}
	return map[string]any{"ok": true}
}

// ---- composition: permissions grant, prohibitions veto -----------------------------------------------------------------

// ComposeAuthority: allow = permitted AND prohibitions ok; the monitor runs unconditionally so denial reasons are complete.
func ComposeAuthority(permitted any, action, constitution, state any) map[string]any {
	return composeFrom(permitted, CheckProhibitions(action, constitution, state))
}

func composeFrom(permitted any, prohibition map[string]any) map[string]any {
	p := permitted == true
	by := "none"
	if prohibition["ok"] != true {
		by = "prohibition"
	} else if !p {
		by = "permission"
	}
	return map[string]any{"allow": p && prohibition["ok"] == true, "decidedBy": by, "permitted": p, "prohibition": prohibition}
}

// CheckAndAdvance is the pure kernel of the server's critical section: CAS guards, compose, evidence over the pre-state, next state on
// allow. opts may carry expectedSeq and expectedStateDigest. Never panics.
func CheckAndAdvance(permitted any, action, constitution, state any, opts map[string]any) (res map[string]any) {
	a, _ := pNorm(action)
	c, _ := pNorm(constitution)
	s, _ := pNorm(state)
	monitored := checkProhibitionsB(a, c, s, &regexBudget{})
	evidence := evidenceFrom(monitored, a, c, s)
	decision := composeFrom(permitted, monitored)
	refuse := func(decidedBy, reason string) map[string]any {
		out := map[string]any{"allow": false, "decidedBy": decidedBy, "evidence": evidence, "prohibition": decision["prohibition"], "next": s}
		if reason != "" {
			out["reason"] = reason
		}
		return out
	}
	defer func() {
		if recover() != nil {
			res = refuse("state", "check-and-advance error (fail closed)")
		}
	}()
	if v, has := opts["expectedSeq"]; has {
		sm, isObj := s.(map[string]any)
		if !isObj || !jeq(sm["seq"], v) {
			return refuse("state", "stale state head (seq)")
		}
	}
	if v, has := opts["expectedStateDigest"]; has {
		if d := safeStr(func() (string, error) { return StateDigest(s) }); jsValueString(v) != d || !isString(v) {
			return refuse("state", "stale state head (digest)")
		}
	}
	if decision["allow"] != true {
		by := decision["decidedBy"].(string)
		if by == "none" {
			by = "permission"
		}
		return refuse(by, "")
	}
	if evidence["ok"] != true {
		return refuse("prohibition", "evidence not attestable")
	}
	adv := AdvanceStateStrict(a, c, s)
	if adv["ok"] != true {
		return refuse("state", "advance failed: "+adv["reason"].(string))
	}
	return map[string]any{"allow": true, "decidedBy": "none", "evidence": evidence, "prohibition": decision["prohibition"], "next": adv["state"]}
}
