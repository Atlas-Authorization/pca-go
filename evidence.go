package pca

// The dispute evidence bundle `pca-intent-evidence` v1 (Intent Layer v2): closed-member shape validation, the deterministic normal
// form, the commitments-only form and the digest that commits to it, the bundle reference and its anchor-log leaf, the accumulator
// cap reader and the validators of the verifier's trust inputs. A bundle is a parsed JSON value (ParseJSONLenient: objects are
// map[string]any, numbers json.Number). The reference's JavaScript semantics are reproduced where a hostile bundle reaches them
// (property reads on any value, Object.keys order, relational comparison, the `||` chain of the sort comparators, the JSON round-trip
// copy), so a malformed bundle gives the same shape error, the same order or the same refusal (an error) as the reference.
//
// The full replay is VerifyEvidenceBundle (evidence_verify.go).

import (
	"errors"
	"fmt"
	"math"
	"sort"
)

const (
	// EvidenceDomain is the hash domain of the bundle digest.
	EvidenceDomain = "atlas-pca/intent-evidence/v1"
	// EvidenceReportDomain is the hash domain of a findings report.
	EvidenceReportDomain = "atlas-pca/intent-evidence-report/v1"
	// EvidenceContentType is the media type of a bundle.
	EvidenceContentType = "application/pca-intent-evidence+json"

	evidAnchorDomain = "atlas-pca/intent-anchor/v1"
)

var evidTopKeys = []string{"v", "kind", "subject", "statement", "session_root", "schema", "root_grant", "maps", "answers", "canary_labels", "canaries",
	"deltas", "pcactns", "verdicts", "accumulator", "facts", "classifier", "offer_sets", "labels", "effects", "settlements", "revocation_epochs", "anchors"}

// ---- JavaScript value helpers ---------------------------------------------------------------------------------------

// evidUndefined is JavaScript `undefined` (a member that is absent); JSON null is Go nil.
type evidUndefined struct{}

var evidUndef any = evidUndefined{}

// evidThrow is a JavaScript exception: raised by panic inside the port and turned into an error at the API boundary.
type evidThrow struct{ msg string }

func evidRaise(msg string) { panic(evidThrow{msg}) }

// evidTry runs f; a JavaScript-style exception (or any panic: fail closed) is an error.
func evidTry(f func() any) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			res = nil
			if t, ok := r.(evidThrow); ok {
				err = errors.New(t.msg)
			} else {
				err = fmt.Errorf("evidence: %v", r)
			}
		}
	}()
	return f(), nil
}

// evidGet is `o[k]` without throwing: evidUndef for an absent member or a value without members.
func evidGet(o any, k string) any {
	switch t := o.(type) {
	case map[string]any:
		if v, ok := t[k]; ok {
			return v
		}
	case []any:
		if k == "length" {
			return jsNumber(float64(len(t)))
		}
		for i := range t {
			if fmt.Sprint(i) == k {
				return t[i]
			}
		}
	case string:
		if k == "length" {
			return jsNumber(float64(jsLen(t)))
		}
	}
	return evidUndef
}

// evidRd is `o[k]` where o must not be null or undefined (a TypeError otherwise).
func evidRd(o any, k string) any {
	if o == nil || o == evidUndef {
		evidRaise("Cannot read properties of " + evidStr(o) + " (reading '" + k + "')")
	}
	return evidGet(o, k)
}

// evidStr is String(v).
func evidStr(v any) string {
	if v == evidUndef {
		return "undefined"
	}
	return jsValueString(v)
}

func evidTruthy(v any) bool { return v != evidUndef && jsTruthy(v) }

func evidToNum(v any) float64 {
	if v == evidUndef {
		return math.NaN()
	}
	return jsToNumber(v)
}

func evidPrim(v any) any {
	switch v.(type) {
	case map[string]any, []any:
		return jsValueString(v)
	}
	return v
}

// evidLess is JavaScript `a < b` (false when either side is NaN).
func evidLess(a, b any) bool {
	a, b = evidPrim(a), evidPrim(b)
	if sa, ok := a.(string); ok {
		if sb, ok := b.(string); ok {
			return compareUnits(utf16Units(sa), utf16Units(sb)) < 0
		}
	}
	return evidToNum(a) < evidToNum(b)
}

func evidCmp(a, b any) float64 {
	if evidLess(a, b) {
		return -1
	}
	if evidLess(b, a) {
		return 1
	}
	return 0
}

func evidSub(a, b any) float64 { return evidToNum(a) - evidToNum(b) }

// evidOr is `first || rest()` for numbers: zero and NaN are falsy.
func evidOr(first float64, rest func() float64) float64 {
	if first != 0 && first == first {
		return first
	}
	return rest()
}

func evidSort(v any, cmp func(a, c any) float64) {
	l, ok := v.([]any)
	if !ok {
		evidRaise("sort is not a function")
	}
	sort.SliceStable(l, func(i, j int) bool { return cmp(l[i], l[j]) < 0 })
}

func evidSortSet(v any) {
	if v == evidUndef || v == nil {
		return
	}
	evidSort(v, func(a, c any) float64 { return evidCmp(evidHash(a), evidHash(c)) })
}

func evidHash(v any) string {
	h, err := HashCanonical(v)
	if err != nil {
		evidRaise(err.Error())
	}
	return h
}

// evidSpread is the members `{...v}` copies: an object's own, an array's or a string's indices, nothing for any other value.
func evidSpread(v any) map[string]any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = x
		}
		return out
	case []any:
		out := make(map[string]any, len(t))
		for i, x := range t {
			out[fmt.Sprint(i)] = x
		}
		return out
	case string:
		u := utf16Units(t)
		out := make(map[string]any, len(u))
		for i := range u {
			out[fmt.Sprint(i)] = string(rune(u[i]))
		}
		return out
	}
	return map[string]any{}
}

// evidPlain is JSON.parse(JSON.stringify(v)): a deep copy with canonical number lexemes, -0 as 0 and a non-finite number as null.
func evidPlain(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = evidPlain(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = evidPlain(x)
		}
		return out
	case nil, bool, string:
		return v
	}
	f, ok := jsNum(v)
	if !ok {
		return v
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil
	}
	if f == 0 {
		return jsNumber(0)
	}
	return jsNumber(f)
}

func evidIsOne(v any) bool { f, ok := jsNum(v); return ok && f == 1 }

func evidIsStr(v any) bool { _, ok := v.(string); return ok }

// ---- shape ----------------------------------------------------------------------------------------------------------

func evidClosed(o any, keys []string, where string) string {
	m, ok := o.(map[string]any)
	if !ok {
		return where + " must be an object"
	}
	for _, k := range jsKeys(m) {
		if !containsStr(keys, k) {
			return where + `: unknown member "` + k + `"`
		}
	}
	return ""
}

func evidObj(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }

// EvidenceBundleShapeError is the closed-member shape validation: unknown members are refused at every level the bundle owns. ""
// when the bundle is well formed.
func EvidenceBundleShapeError(b any) string {
	if e := evidClosed(b, evidTopKeys, "bundle"); e != "" {
		return e
	}
	x := b.(map[string]any)
	if !evidIsOne(x["v"]) || x["kind"] != "pca-intent-evidence" {
		return "not a pca-intent-evidence v1 bundle"
	}
	if e := evidClosed(x["subject"], []string{"pcactn_digest", "aud", "session"}, "subject"); e != "" {
		return e
	}
	s := x["subject"].(map[string]any)
	if !evidIsStr(s["pcactn_digest"]) || !evidIsStr(s["aud"]) || !evidIsStr(s["session"]) {
		return "subject members must be strings"
	}
	if e := evidClosed(x["statement"], []string{"commit", "opening"}, "statement"); e != "" {
		return e
	}
	if !evidIsStr(x["statement"].(map[string]any)["commit"]) {
		return "statement.commit must be a string"
	}
	sr, ok := evidObj(x["session_root"])
	if !ok || !evidIsOne(sr["v"]) || sr["kind"] != "pca-intent-session" {
		return "session_root is not a pca-intent-session v1"
	}
	if !evidIsStr(sr["session"]) || !evidIsStr(sr["intent_ref"]) || !jsIsInt(sr["expires_at"]) {
		return "session_root is missing session / intent_ref / expires_at"
	}
	pr, isArr := sr["principals"].([]any)
	okKeys := isArr && len(pr) > 0
	for _, p := range pr {
		pm, isMap := evidObj(p)
		okKeys = okKeys && isMap && evidIsStr(pm["key"])
	}
	if !okKeys {
		return "session_root.principals must be a non-empty key list"
	}
	if e := evidClosed(x["schema"], []string{"doc", "anchor"}, "schema"); e != "" {
		return e
	}
	doc, ok := evidObj(x["schema"].(map[string]any)["doc"])
	if _, sigObj := evidObj(doc["sig"]); !ok || doc["kind"] != "pca-action-schema" || !sigObj {
		return "schema.doc is not a signed pca-action-schema"
	}
	if _, ok := evidObj(x["root_grant"]); !ok {
		return "root_grant must be a capability"
	}
	for _, k := range []string{"maps", "answers", "canary_labels", "deltas", "pcactns", "verdicts", "effects", "revocation_epochs", "anchors"} {
		if _, ok := x[k].([]any); !ok {
			return k + " must be an array"
		}
	}
	for _, k := range []string{"facts", "classifier", "offer_sets", "labels", "settlements"} {
		if v, has := x[k]; has {
			if _, ok := v.([]any); !ok {
				return k + " must be an array"
			}
		}
	}
	for i, m := range x["maps"].([]any) {
		if e := evidClosed(m, []string{"seq", "commit", "map", "disclosed"}, fmt.Sprintf("maps[%d]", i)); e != "" {
			return e
		}
		mm := m.(map[string]any)
		if seq, _ := jsNum(mm["seq"]); !jsIsInt(mm["seq"]) || seq < 0 || !evidIsStr(mm["commit"]) {
			return fmt.Sprintf("maps[%d] needs an integer seq and a commit", i)
		}
	}
	for i, c := range x["canary_labels"].([]any) {
		if e := evidClosed(c, []string{"question_id", "label"}, fmt.Sprintf("canary_labels[%d]", i)); e != "" {
			return e
		}
		cc := c.(map[string]any)
		lab, isNum := jsNum(cc["label"])
		if !evidIsStr(cc["question_id"]) || !isNum || (lab != 0 && lab != 1) {
			return fmt.Sprintf("canary_labels[%d] is malformed", i)
		}
	}
	if e := evidClosed(x["canaries"], []string{"asked", "false_yes", "false_no"}, "canaries"); e != "" {
		return e
	}
	cn := x["canaries"].(map[string]any)
	for _, k := range []string{"asked", "false_yes", "false_no"} {
		if !jsIsNonNeg(cn[k]) {
			return "canaries counts must be non-negative integers"
		}
	}
	if e := evidClosed(x["accumulator"], []string{"holder", "events", "receipts", "sequencer_keys"}, "accumulator"); e != "" {
		return e
	}
	acc := x["accumulator"].(map[string]any)
	if acc["holder"] != "site_local" && acc["holder"] != "sequenced" {
		return "accumulator.holder must be site_local or sequenced"
	}
	events, ok := acc["events"].([]any)
	if !ok {
		return "accumulator.events must be an array"
	}
	for i, ev := range events {
		if e := evidClosed(ev, []string{"acc", "post", "pcactn_digest", "delta", "status"}, fmt.Sprintf("accumulator.events[%d]", i)); e != "" {
			return e
		}
		evv := ev.(map[string]any)
		if !evidIsStr(evv["acc"]) || !jsIsNonNeg(evv["post"]) || !evidIsStr(evv["pcactn_digest"]) {
			return fmt.Sprintf("accumulator.events[%d] is malformed", i)
		}
		if d, has := evv["delta"]; has && !jsIsNonNeg(d) {
			return fmt.Sprintf("accumulator.events[%d].delta must be a non-negative integer", i)
		}
	}
	if r, has := acc["receipts"]; has {
		if _, ok := r.([]any); !ok {
			return "accumulator.receipts must be an array"
		}
	}
	if r, has := acc["sequencer_keys"]; has {
		if _, ok := r.([]any); !ok {
			return "accumulator.sequencer_keys must be an array"
		}
	}
	for i, r := range x["revocation_epochs"].([]any) {
		if e := evidClosed(r, []string{"epoch", "revoked"}, fmt.Sprintf("revocation_epochs[%d]", i)); e != "" {
			return e
		}
		rr := r.(map[string]any)
		_, epochObj := evidObj(rr["epoch"])
		_, revokedArr := rr["revoked"].([]any)
		if !epochObj || !revokedArr {
			return fmt.Sprintf("revocation_epochs[%d] needs an epoch and its revoked list", i)
		}
	}
	for i, a := range x["anchors"].([]any) {
		if e := evidClosed(a, []string{"kind", "digest", "index", "proof", "signed_tree_head"}, fmt.Sprintf("anchors[%d]", i)); e != "" {
			return e
		}
	}
	for i, ef := range x["effects"].([]any) {
		em, ok := evidObj(ef)
		if !ok || !evidIsStr(em["pcactn_digest"]) {
			return fmt.Sprintf("effects[%d] needs a pcactn_digest", i)
		}
	}
	return ""
}

// ---- normal form ----------------------------------------------------------------------------------------------------

// evidSeqOf is the `seq` of a grant's first `intent_session` caveat (the largest safe integer when it has none).
func evidSeqOf(c any) float64 {
	cvs, ok := evidRd(c, "caveats").([]any)
	if !ok {
		evidRaise("c.caveats.find is not a function")
	}
	for _, k := range cvs {
		if evidRd(k, "type") == "intent_session" {
			if seq := evidGet(k, "seq"); jsIsInt(seq) {
				return jsF(seq)
			}
			return maxSafeInt
		}
	}
	return maxSafeInt
}

// evidEffectKey is the hash of an effect record without its params opening (`const {params, ...k} = e`).
func evidEffectKey(e any) string {
	if e == nil || e == evidUndef {
		evidRaise("Cannot destructure a null or undefined value")
	}
	k := evidSpread(e)
	delete(k, "params")
	return evidHash(k)
}

func evidNormalize(b any) any {
	x := evidPlain(b)
	r := evidRd
	evidSort(r(x, "maps"), func(a, c any) float64 {
		return evidOr(evidSub(r(a, "seq"), r(c, "seq")), func() float64 { return evidCmp(r(a, "commit"), r(c, "commit")) })
	})
	evidSort(r(x, "answers"), func(a, c any) float64 {
		return evidOr(evidSub(r(a, "observed_at"), r(c, "observed_at")), func() float64 {
			return evidOr(evidCmp(r(a, "question_id"), r(c, "question_id")), func() float64 { return evidCmp(r(a, "sig"), r(c, "sig")) })
		})
	})
	evidSort(r(x, "canary_labels"), func(a, c any) float64 {
		return evidOr(evidCmp(r(a, "question_id"), r(c, "question_id")), func() float64 { return evidSub(r(a, "label"), r(c, "label")) })
	})
	evidSort(r(x, "deltas"), func(a, c any) float64 {
		return evidOr(evidSeqOf(a)-evidSeqOf(c), func() float64 { return evidCmp(r(a, "id"), r(c, "id")) })
	})
	evidSort(r(x, "pcactns"), func(a, c any) float64 {
		return evidOr(evidSub(r(a, "iat"), r(c, "iat")), func() float64 {
			return evidOr(evidSub(r(a, "counter"), r(c, "counter")), func() float64 { return evidCmp(evidHash(a), evidHash(c)) })
		})
	})
	evidSort(r(x, "verdicts"), func(a, c any) float64 {
		return evidOr(evidCmp(r(a, "pcactn_digest"), r(c, "pcactn_digest")), func() float64 { return evidCmp(evidHash(a), evidHash(c)) })
	})
	// sorted without the params opening, so withholding an opening never reorders the commitments-only form
	evidSort(r(x, "effects"), func(a, c any) float64 {
		return evidOr(evidCmp(r(a, "pcactn_digest"), r(c, "pcactn_digest")), func() float64 { return evidCmp(evidEffectKey(a), evidEffectKey(c)) })
	})
	// issue order (not epoch number): a rollback, an epoch issued later with a lower number, must stay visible
	ep := func(o any, k string) any { return r(r(o, "epoch"), k) }
	evidSort(r(x, "revocation_epochs"), func(a, c any) float64 {
		return evidOr(evidSub(ep(a, "issued_at"), ep(c, "issued_at")), func() float64 {
			return evidOr(evidSub(ep(a, "epoch"), ep(c, "epoch")), func() float64 { return evidCmp(evidHash(a), evidHash(c)) })
		})
	})
	evidSort(r(x, "anchors"), func(a, c any) float64 {
		return evidOr(evidCmp(r(a, "kind"), r(c, "kind")), func() float64 {
			return evidOr(evidSub(r(a, "index"), r(c, "index")), func() float64 { return evidCmp(r(a, "digest"), r(c, "digest")) })
		})
	})
	for _, k := range []string{"facts", "classifier", "offer_sets", "labels", "settlements"} {
		evidSortSet(evidGet(x, k))
	}
	if receipts := evidGet(r(x, "accumulator"), "receipts"); evidTruthy(receipts) {
		evidSort(receipts, func(a, c any) float64 { return evidCmp(evidHash(a), evidHash(c)) })
	}
	return x
}

// NormalizeEvidenceBundle is the deterministic normal form. Members that are SETS (answers, deltas, PCActns, verdicts, effects,
// epochs, anchors, maps, canary labels) are sorted by a content key, so two exports of the same evidence produce the same bytes
// whatever order the site stored them in; `accumulator.events` is a SEQUENCE and is never reordered. The input is not modified. An
// error for a bundle that cannot be put in order (a refusal, as the reference throws).
func NormalizeEvidenceBundle(b any) (any, error) {
	return evidTry(func() any { return evidNormalize(b) })
}

// BuildEvidenceBundle assembles a bundle from its parts (everything but v and kind) in normal form. An error on a malformed part
// (the exporter's bug, not evidence).
func BuildEvidenceBundle(parts any) (any, error) {
	return evidTry(func() any {
		b := map[string]any{"v": jsNumber(1), "kind": "pca-intent-evidence"}
		for k, v := range evidSpread(parts) {
			b[k] = v
		}
		n := evidNormalize(b)
		if bad := EvidenceBundleShapeError(n); bad != "" {
			evidRaise("buildEvidenceBundle: " + bad)
		}
		return n
	})
}

// evidCommitment is the commitments-only form and whether a committed member is undefined (an undefined member cannot be hashed).
func evidCommitment(b any) (map[string]any, bool) {
	n := evidNormalize(b).(map[string]any)
	rest := make(map[string]any, len(n))
	for k, v := range n {
		if k != "anchors" {
			rest[k] = v
		}
	}
	undef := false
	statement := evidRd(n, "statement")
	commit := evidRd(statement, "commit")
	st := map[string]any{}
	if commit == evidUndef {
		undef = true
	} else {
		st["commit"] = commit
	}
	rest["statement"] = st
	maps := []any{}
	for _, m := range n["maps"].([]any) {
		entry := map[string]any{}
		for _, k := range []string{"seq", "commit"} {
			if v := evidRd(m, k); v == evidUndef {
				undef = true
			} else {
				entry[k] = v
			}
		}
		if d := evidGet(m, "disclosed"); d != evidUndef {
			entry["disclosed"] = d
		}
		maps = append(maps, entry)
	}
	rest["maps"] = maps
	effects := []any{}
	for _, e := range n["effects"].([]any) {
		if e == nil || e == evidUndef {
			evidRaise("Cannot destructure a null or undefined value")
		}
		kept := evidSpread(e)
		delete(kept, "params")
		effects = append(effects, kept)
	}
	rest["effects"] = effects
	return rest, undef
}

// EvidenceCommitmentForm is the commitments-only normal form: no anchors, no statement opening, no full maps, no effect params;
// every signed artifact and every claim stays in.
func EvidenceCommitmentForm(b any) (any, error) {
	return evidTry(func() any { f, _ := evidCommitment(b); return f })
}

// EvidenceBundleDigest is the bundle's content address: the hash over the commitments-only normal form. Anchors, SCITT and the CLI use it.
func EvidenceBundleDigest(b any) (string, error) {
	r, err := evidTry(func() any {
		form, undef := evidCommitment(b)
		if undef {
			evidRaise("canonicalize: undefined member")
		}
		return evidHash(map[string]any{"d": EvidenceDomain, "b": form})
	})
	if err != nil {
		return "", err
	}
	return r.(string), nil
}

// EvidenceRef is the public reference to a bundle: {kind: "pca-intent-evidence-ref", digest, subject}. The bundle itself stays
// with the site.
func EvidenceRef(bundle any) (map[string]any, error) {
	d, err := EvidenceBundleDigest(bundle)
	if err != nil {
		return nil, err
	}
	r, err := evidTry(func() any {
		return map[string]any{"kind": "pca-intent-evidence-ref", "digest": d, "subject": evidSpread(evidRd(bundle, "subject"))}
	})
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

// EvidenceAnchorCommitOf is the intent-log leaf for an anchored artifact (any kind).
func EvidenceAnchorCommitOf(kind, digest string) (string, error) {
	return HashCanonical(map[string]any{"d": evidAnchorDomain, "kind": kind, "digest": digest})
}

// EvidenceAnchorCommit is the intent-anchor-log leaf for a bundle digest (kind `evidence`).
func EvidenceAnchorCommit(digest string) (string, error) {
	return EvidenceAnchorCommitOf("evidence", digest)
}

// ---- accumulator cap ------------------------------------------------------------------------------------------------

func evidLeafCaps(conds any, path string) []float64 {
	var items []any
	switch t := conds.(type) {
	case nil:
	case []any:
		items = t
	case string: // `for of` over a string visits its characters, none a condition
	default:
		if conds != evidUndef {
			evidRaise("conds is not iterable")
		}
	}
	var out []float64
	for _, c := range items {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		_, all := m["all_of"]
		_, any_ := m["any_of"]
		_, not := m["not"]
		if all || any_ || not { // a group
			if all {
				out = append(out, evidLeafCaps(m["all_of"], path)...)
			}
			continue
		}
		if f, isStr := m["field"].(string); !isStr || f != path { // not a leaf, or another field
			continue
		}
		if _, hasRef := m["ref"]; hasRef {
			continue
		}
		v, isNum := jsNum(m["value"])
		if !isNum {
			continue
		}
		switch m["op"] {
		case "lte":
			out = append(out, v)
		case "lt":
			out = append(out, v-1)
		}
	}
	return out
}

// EvidenceCapOf is the cap `env.acc.<id>.post <= v` that the grant's envelope states for verb: per predicate the tightest bound in
// its `where` (descending into `all_of`); across predicates (a union) the loosest. The result is nil when a predicate admitting the
// verb states no bound, or none admits it. An error where the reference throws on a hostile grant.
func EvidenceCapOf(grant any, accID, verb string) (any, error) {
	return evidTry(func() any {
		env := ReadEnvelope(grant)
		if env == nil {
			return nil
		}
		path := "env.acc." + accID + ".post"
		var cap *float64
		for _, p := range env["predicates"].([]any) {
			var verbs []string
			if l, ok := evidRd(p, "verb").([]any); ok {
				for _, x := range l {
					verbs = append(verbs, evidStr(x))
				}
			} else {
				verbs = []string{evidStr(evidRd(p, "verb"))}
			}
			if !containsStr(verbs, verb) && !containsStr(verbs, "*") {
				continue
			}
			caps := evidLeafCaps(evidGet(p, "where"), path)
			if len(caps) == 0 {
				return nil
			}
			m := caps[0]
			for _, c := range caps[1:] {
				m = math.Min(m, c)
			}
			if cap == nil {
				cap = &m
			} else {
				mx := math.Max(*cap, m)
				cap = &mx
			}
		}
		if cap == nil {
			return nil
		}
		return jsNumber(*cap)
	})
}

// ---- trust-input validators -----------------------------------------------------------------------------------------

// EvidencePrincipalsTrustError validates `trust.principals`: a non-empty array of closed {key, pq_pk?} with canonical keys. ""
// when valid. present false is an absent value (valid); a JSON null is present with a nil value.
func EvidencePrincipalsTrustError(p any, present bool) string {
	if !present {
		return ""
	}
	l, ok := p.([]any)
	if !ok || len(l) == 0 {
		return "trust.principals must be a non-empty array of {key, pq_pk?}"
	}
	for i, x := range l {
		m, ok := x.(map[string]any)
		if !ok {
			return fmt.Sprintf("trust.principals[%d] must be an object {key, pq_pk?}", i)
		}
		for _, k := range jsKeys(m) {
			if k != "key" && k != "pq_pk" {
				return fmt.Sprintf("trust.principals[%d]: unknown member '%s'", i, k)
			}
		}
		if k, isStr := m["key"].(string); !isStr || !b64uOK(k, 32) {
			return fmt.Sprintf("trust.principals[%d].key must be canonical base64url (32 bytes)", i)
		}
		if pq, has := m["pq_pk"]; has {
			if s, isStr := pq.(string); !isStr || !b64uOK(s, -1) {
				return fmt.Sprintf("trust.principals[%d].pq_pk must be canonical base64url", i)
			}
		}
	}
	return ""
}

// EvidenceAccTrustError validates `trust.acc` like the core `policy.acc`: closed members, non-negative safe integers. "" when
// valid; present false is an absent value (valid).
func EvidenceAccTrustError(a any, present bool) string {
	if !present {
		return ""
	}
	m, ok := a.(map[string]any)
	if !ok {
		return "trust.acc must be an object"
	}
	for _, k := range jsKeys(m) {
		if k != "max_receipt_age_s" && k != "max_keyset_age_s" {
			return "trust.acc: unknown member '" + k + "'"
		}
		if !jsIsNonNeg(m[k]) {
			return "trust.acc." + k + " must be a non-negative safe integer"
		}
	}
	return ""
}
