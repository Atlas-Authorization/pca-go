package pca

// Least privilege from observed behaviour: propose a narrower grant from what its holder really did (proven subsumed by the original,
// never applied), unused-permission findings, and signed access requests.

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

const anlAccessRequestSigDomain = "atlas-pca/access-request/v1\x00"

func anlRevWeight(r any) float64 {
	if s, ok := r.(string); ok {
		for i, x := range anlRevOrder {
			if x == s {
				return float64(i + 1)
			}
		}
	}
	return 0
}

// anlResolveAction is the spec of a catalogued verb, else the fail-closed spec (irreversible, maximum blast radius).
func anlResolveAction(catalog any, verb any) map[string]any {
	v := anlJS(verb)
	if catalog == nil || anlIsUndef(catalog) {
		for _, a := range BuiltinActions {
			if a.Verb == v {
				return map[string]any{"blastRadius": a.BlastRadius, "reversibility": a.Reversibility}
			}
		}
	} else if m, ok := catalog.(map[string]any); ok {
		if s, ok := m[v].(map[string]any); ok {
			return s
		}
	} else if l, ok := catalog.([]any); ok {
		var found map[string]any
		for _, a := range l {
			if am, ok := a.(map[string]any); ok && am["verb"] == v {
				found = am
			}
		}
		if found != nil {
			return found
		}
	}
	return map[string]any{"blastRadius": 1, "reversibility": "irreversible"}
}

func anlCommonPrefix(rs []string) string {
	p := []rune{}
	if len(rs) > 0 {
		p = []rune(rs[0])
	}
	for _, r := range rs {
		rr := []rune(r)
		i := 0
		for i < len(p) && i < len(rr) && p[i] == rr[i] {
			i++
		}
		p = p[:i]
	}
	s := string(p)
	if cut := strings.LastIndex(s, "/"); cut >= 0 {
		return s[:cut+1]
	}
	return ""
}

func anlIsIntegerNum(v any) bool {
	f := anlToNumber(v)
	return anlIsNum(v) && !math.IsInf(f, 0) && !math.IsNaN(f) && f == math.Trunc(f)
}

func anlUpperBoundOf(where any, path string) float64 {
	ub := anlInf
	for _, c := range anlReqList(anlNN(where, []any{})) {
		m, ok := c.(map[string]any)
		if !ok || !anlHas(m, "field") || m["field"] != path {
			continue
		}
		if op := anlOwn(m, "op"); (op == "lte" || op == "lt") && anlIsNum(anlOwn(m, "value")) {
			ub = math.Min(ub, anlToNumber(m["value"]))
		}
	}
	return ub
}

func anlNarrowCtx(a any) map[string]any {
	act := map[string]any{}
	if v := anlGet(a, "verb"); !anlIsUndef(v) {
		act["verb"] = v
	}
	if v := anlGet(a, "resource"); !anlIsUndef(v) {
		act["resource"] = v
	}
	params := anlGet(a, "params")
	if anlIsUndef(params) || params == nil {
		params = map[string]any{}
	}
	act["params"] = params
	return map[string]any{"action": act}
}

func anlNarrowMatches(p, a any) bool { return predicateMatches(p, anlNarrowCtx(a), &regexBudget{}) }

func anlParamsOf(a any) any { return anlNN(anlGet(a, "params"), map[string]any{}) }

func anlSortStrs(set []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range set {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return anlUnitLess(out[i], out[j]) })
	return out
}

func anlStrsToAny(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

func anlFinding(kind string, i int, spec map[string]any) map[string]any {
	br := anlToNumber(spec["blastRadius"])
	return map[string]any{"kind": kind, "predicate": i, "blastRadius": br, "reversibility": spec["reversibility"], "rank": br * anlRevWeight(spec["reversibility"])}
}

// anlSuggestNarrowing proposes a narrower replacement for `policy` from the ledger-sourced `observed` actions, plus unused-permission
// findings and access requests for refused attempts. Never applies anything.
func anlSuggestNarrowing(policy, observedIn, optsIn any) map[string]any {
	o := optsIn
	if o == nil || anlIsUndef(o) {
		o = map[string]any{}
	}
	margin := anlToNumber(anlNN(anlGet(o, "margin"), 0.1))
	minSamples := anlToNumber(anlNN(anlGet(o, "minSamples"), 5))
	enumLimit := anlToNumber(anlNN(anlGet(o, "enumLimit"), 8))
	catalog := anlGet(o, "catalog")
	model := anlToModel(policy)
	digest := anlPolicyDigestOf(model)
	observed := anlReqList(observedIn)

	var trusted, refused []any
	rejected := 0
	for _, x := range observed {
		src, out := anlGet(x, "source"), anlGet(x, "outcome")
		if src == "ledger" && out != "denied" {
			trusted = append(trusted, x)
		}
		if src != "ledger" {
			rejected++
		}
		if src == "ledger" && out == "denied" {
			refused = append(refused, x)
		}
	}
	findings := []any{}
	var base []any
	if pp, ok := anlGet(policy, "predicates").([]any); ok {
		base = pp
	}

	build := func(narrow bool) []any {
		out := []any{}
		for _, p := range base {
			var hits []any
			for _, a := range trusted {
				if anlNarrowMatches(p, a) {
					hits = append(hits, a)
				}
			}
			if len(hits) == 0 {
				continue
			}
			var vs, rs []string
			for _, h := range hits {
				vs = append(vs, anlStr(anlGet(h, "verb"), "verb"))
				rs = append(rs, anlStr(anlGet(h, "resource"), "resource"))
			}
			verbs, resources := anlSortStrs(vs), anlSortStrs(rs)
			nxt := map[string]any{}
			if len(verbs) == 1 {
				nxt["verb"] = verbs[0]
			} else {
				nxt["verb"] = anlStrsToAny(verbs)
			}
			pres := anlGet(p, "resource")
			if narrow {
				if len(resources) == 1 {
					nxt["resource"] = resources[0]
				} else if pre := anlCommonPrefix(resources); len([]rune(pre)) > 1 {
					nxt["resource"] = pre + "*"
				} else if !anlIsUndef(pres) {
					nxt["resource"] = pres
				}
			} else if !anlIsUndef(pres) {
				nxt["resource"] = pres
			}
			where := append([]any{}, anlReqList(anlNN(anlGet(p, "where"), []any{}))...)
			var names []string
			for _, h := range hits {
				for k := range anlSpread(anlParamsOf(h)) {
					names = append(names, k)
				}
			}
			for _, name := range anlSortStrs(names) {
				path := "action.params." + name
				var vals []any
				missing := false
				for _, h := range hits {
					v := anlOwn(anlParamsOf(h), name)
					if anlIsUndef(v) {
						missing = true
					}
					vals = append(vals, v)
				}
				if float64(len(vals)) < minSamples || missing {
					continue
				}
				allNum, allStr, allInt := true, true, true
				mx := math.Inf(-1)
				for _, v := range vals {
					if !anlIsFin(v) {
						allNum = false
					} else {
						mx = math.Max(mx, anlToNumber(v))
					}
					if _, ok := v.(string); !ok {
						allStr = false
					}
					if !anlIsIntegerNum(v) {
						allInt = false
					}
				}
				if allNum {
					v := mx * (1 + margin)
					ceil := v
					if allInt {
						ceil = math.Ceil(v)
					}
					if ceil < anlUpperBoundOf(anlGet(p, "where"), path) {
						where = append(where, map[string]any{"field": path, "op": "lte", "value": ceil})
					}
				} else if allStr {
					var ss []string
					for _, v := range vals {
						ss = append(ss, v.(string))
					}
					st := anlSortStrs(ss)
					if float64(len(st)) <= enumLimit {
						where = append(where, map[string]any{"field": path, "op": "in", "value": anlStrsToAny(st)})
					}
				}
			}
			if len(where) > 0 {
				nxt["where"] = where
			}
			out = append(out, nxt)
		}
		return out
	}

	for i, p := range base {
		hit := false
		for _, a := range trusted {
			if anlNarrowMatches(p, a) {
				hit = true
				break
			}
		}
		pv := anlGet(p, "verb")
		var verbs []any
		if s, ok := pv.(string); ok {
			verbs = []any{s}
		} else if l, ok := pv.([]any); ok {
			verbs = l
		}
		if !hit {
			var v any = "*"
			if len(verbs) > 0 && verbs[0] != nil {
				v = verbs[0]
			}
			name := v
			if v == "*" {
				name = "unknown.any"
			}
			f := anlFinding("unused-predicate", i, anlResolveAction(catalog, name))
			f["verb"] = v
			var js []string
			for _, x := range verbs {
				if x == nil {
					js = append(js, "")
				} else {
					js = append(js, anlJS(x))
				}
			}
			joined := strings.Join(js, ", ")
			if joined == "" {
				joined = "*"
			}
			f["detail"] = fmt.Sprintf("no observed action used predicate %d (%s)", i, joined)
			findings = append(findings, f)
			continue
		}
		for _, v := range verbs {
			if v == "*" {
				continue
			}
			used := false
			for _, a := range trusted {
				if anlStrictEq(anlGet(a, "verb"), v) && anlNarrowMatches(p, a) {
					used = true
					break
				}
			}
			if !used {
				f := anlFinding("unused-verb", i, anlResolveAction(catalog, v))
				f["verb"] = v
				f["detail"] = fmt.Sprintf("verb %s is granted by predicate %d but never used", anlJS(v), i)
				findings = append(findings, f)
			}
		}
		for _, c := range anlReqList(anlNN(anlGet(p, "where"), []any{})) {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			field, isStr := cm["field"].(string)
			op := anlOwn(cm, "op")
			if !isStr || !(op == "lte" || op == "lt") || !anlIsNum(anlOwn(cm, "value")) || !strings.HasPrefix(field, "action.params.") {
				continue
			}
			name := field[len("action.params."):]
			var vals []float64
			for _, a := range trusted {
				if anlNarrowMatches(p, a) {
					if x := anlOwn(anlParamsOf(a), name); anlIsNum(x) {
						vals = append(vals, anlToNumber(x))
					}
				}
			}
			if float64(len(vals)) < minSamples {
				continue
			}
			if len(vals) == 0 {
				anlFail("max() of an empty sequence")
			}
			top := vals[0]
			for _, x := range vals {
				top = math.Max(top, x)
			}
			capv := anlToNumber(cm["value"])
			if top < capv/2 {
				var v0 any = anlUndef
				if len(verbs) > 0 {
					v0 = verbs[0]
				}
				var rv any = "unknown.any"
				if !anlIsUndef(v0) && v0 != nil {
					rv = v0
				}
				f := anlFinding("unreached-cap", i, anlResolveAction(catalog, rv))
				if anlTruthy(v0) {
					f["verb"] = v0
				}
				f["detail"] = fmt.Sprintf("%s <= %s but the largest observed value is %s", name, anlNumStr(capv), anlNumStr(top))
				findings = append(findings, f)
			}
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i].(map[string]any), findings[j].(map[string]any)
		if a["rank"].(float64) != b["rank"].(float64) {
			return a["rank"].(float64) > b["rank"].(float64)
		}
		return a["predicate"].(int) < b["predicate"].(int)
	})

	var groupOrder []map[string]any
	groups := map[string]map[string]any{}
	for _, a := range refused {
		k := anlJS(anlGet(a, "verb")) + "\x00" + anlJS(anlGet(a, "resource"))
		if g := groups[k]; g != nil {
			g["denied_count"] = g["denied_count"].(int) + 1
			continue
		}
		r := anlU(map[string]any{
			"v": 1, "kind": "pca-access-request", "verb": anlGet(a, "verb"), "resource": anlGet(a, "resource"),
			"example_params": anlSpread(anlParamsOf(a)), "denied_count": 1, "policy_digest": digest,
		})
		if tb := anlGet(o, "taskBinding"); anlTruthy(tb) {
			r["task_binding"] = tb
		}
		groups[k] = r
		groupOrder = append(groupOrder, r)
	}
	sort.SliceStable(groupOrder, func(i, j int) bool {
		a, b := groupOrder[i], groupOrder[j]
		if a["denied_count"].(int) != b["denied_count"].(int) {
			return a["denied_count"].(int) > b["denied_count"].(int)
		}
		return anlUnitLess(anlStr(a["verb"], "verb"), anlStr(b["verb"], "verb"))
	})
	accessRequests := make([]any, len(groupOrder))
	for i, g := range groupOrder {
		accessRequests[i] = g
	}

	res := map[string]any{"used": len(trusted), "rejected": rejected, "denied": len(refused), "coversObserved": false, "findings": findings, "accessRequests": accessRequests}
	if tb := anlGet(o, "taskBinding"); anlTruthy(tb) {
		res["taskBinding"] = tb
	}
	caveats := []any{}
	if cv, ok := model["caveats"].([]any); ok {
		caveats = append(caveats, cv...)
	}
	if decay := anlGet(o, "decay"); anlTruthy(decay) {
		caveats = append(caveats, map[string]any{"type": "expires", "at": anlToNumber(anlGet(decay, "nowSec")) + anlToNumber(anlGet(decay, "expiresInSecs"))})
	}
	for _, narrow := range []bool{true, false} {
		preds := build(narrow)
		proposal := map[string]any{"predicates": preds, "caveats": caveats, "vetoes": model["vetoes"], "tighten": model["tighten"]}
		if len(preds) == 0 {
			res["reason"] = "no ledger observation matches any predicate"
			return res
		}
		proof := anlSubsumes(policy, proposal, nil)
		if proof["subsumes"] != true || proof["approximate"] == true {
			if r, has := proof["reason"]; has {
				res["reason"] = r
			} else {
				res["reason"] = "the proposal could not be proven narrower than the original"
			}
			continue
		}
		delete(res, "reason")
		res["proposal"] = proposal
		covers := true
		for _, a := range trusted {
			act := anlU(map[string]any{"verb": anlGet(a, "verb"), "resource": anlGet(a, "resource"), "params": anlParamsOf(a)})
			if !anlAdmitsConcrete(proposal, act) {
				covers = false
				break
			}
		}
		res["coversObserved"] = covers
		res["diff"] = anlDiffPolicies(policy, proposal, nil)
		return res
	}
	return res
}

// ---- access requests ----------------------------------------------------------------------------------------------------------

func anlRequestMessage(r any) []byte {
	h, err := HashCanonical(r)
	if err != nil {
		anlFail("request hash: %v", err)
	}
	return append([]byte(anlAccessRequestSigDomain), sha([]byte(h))...)
}

// anlSignAccessRequest is the holder's signed ask (a request for a human to read; nothing here turns it into authority).
func anlSignAccessRequest(r any, kp *KeyPair) map[string]any {
	return map[string]any{"request": r, "signer": kp.Public, "sig": b64.EncodeToString(kp.Sign(anlRequestMessage(r)))}
}

// anlVerifyAccessRequest verifies a signed access request, optionally against an expected signer public key; any failure is false.
func anlVerifyAccessRequest(sv any, expected any) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	s, isObj := sv.(map[string]any)
	if !isObj {
		return false
	}
	req, isObj := s["request"].(map[string]any)
	if !isObj || req["kind"] != "pca-access-request" || !anlStrictEq(anlOwn(req, "v"), 1) {
		return false
	}
	if expected != nil && !anlStrictEq(anlOwn(s, "signer"), expected) {
		return false
	}
	sig, isStr := s["sig"].(string)
	if !isStr {
		return false
	}
	signer, _ := s["signer"].(string)
	pk, ok1 := DecodeB64uStrict(signer, 32)
	sg, ok2 := DecodeB64uStrict(sig, 64)
	if !ok1 || !ok2 {
		return false
	}
	return VerifyStrict(pk, anlRequestMessage(req), sg)
}
