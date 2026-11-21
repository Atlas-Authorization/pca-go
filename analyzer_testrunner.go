package pca

// The policy-as-code test runner: boundary-test generation, running a test document, and signed test documents.

import (
	"fmt"
)

const (
	anlPolicyTestsKind      = "pca-policy-tests"
	anlPolicyTestsSigDomain = "atlas-pca/policy-tests/v1\x00"
)

func anlPolicyTestsDoc(policy, cases any) map[string]any {
	return map[string]any{"v": 1, "kind": anlPolicyTestsKind, "policy_digest": anlPolicyDigestOf(anlToModel(policy)), "cases": cases}
}

// anlRunPolicyTests runs a test document against a policy: {total, passed, failures, digestMatch, ok}. With `requireDigest` a changed
// policy fails even if every case still passes.
func anlRunPolicyTests(policy, doc, optsIn any) map[string]any {
	opts := optsIn
	if opts == nil || anlIsUndef(opts) {
		opts = map[string]any{}
	}
	model := anlToModel(policy)
	failures := []any{}
	cases := anlReqList(anlGet(doc, "cases"))
	for _, c := range cases {
		w := anlWitnessOf(model, anlGet(c, "action"))
		decidedBy := w["winner"].(map[string]any)["id"]
		expBy := anlGet(c, "decidedBy")
		if !anlStrictEq(w["decision"], anlGet(c, "expect")) || (!anlIsUndef(expBy) && !anlStrictEq(expBy, decidedBy)) {
			f := anlU(map[string]any{"name": anlGet(c, "name"), "expected": anlGet(c, "expect"), "got": w["decision"], "decidedBy": decidedBy})
			if !anlIsUndef(expBy) {
				f["expectedDecidedBy"] = expBy
			}
			failures = append(failures, f)
		}
	}
	digestMatch := anlStrictEq(anlGet(doc, "policy_digest"), anlPolicyDigestOf(model))
	return map[string]any{
		"total": len(cases), "passed": len(cases) - len(failures), "failures": failures, "digestMatch": digestMatch,
		"ok": len(failures) == 0 && (anlGet(opts, "requireDigest") != true || digestMatch),
	}
}

func anlPolicyTestsMessage(doc any) []byte {
	h, err := HashCanonical(doc)
	if err != nil {
		anlFail("document hash: %v", err)
	}
	return append([]byte(anlPolicyTestsSigDomain), sha([]byte(h))...)
}

// anlSignPolicyTests: the principal signs the confirmed examples.
func anlSignPolicyTests(doc any, kp *KeyPair) map[string]any {
	return map[string]any{"doc": doc, "signer": kp.Public, "sig": b64.EncodeToString(kp.Sign(anlPolicyTestsMessage(doc)))}
}

func anlVerifyPolicyTests(s any, expected any) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if !anlStrictEq(anlGet(s, "signer"), expected) {
		return false
	}
	d := anlGet(s, "doc")
	if anlIsUndef(d) || d == nil || anlGet(d, "kind") != anlPolicyTestsKind {
		return false
	}
	sig, isStr := anlGet(s, "sig").(string)
	if !isStr {
		return false
	}
	signer, _ := anlGet(s, "signer").(string)
	pk, ok1 := DecodeB64uStrict(signer, 32)
	msg := anlPolicyTestsMessage(d)
	sg, ok2 := DecodeB64uStrict(sig, 64)
	if !ok1 || !ok2 {
		return false
	}
	return VerifyStrict(pk, msg, sg)
}

func anlParamPaths(p any) []string {
	set := &anlSet{}
	var walk func(c any)
	walk = func(c any) {
		m, ok := c.(map[string]any)
		if !ok {
			return
		}
		if f, ok := m["field"].(string); ok && len(f) >= 14 && f[:14] == "action.params." {
			set.add(f)
		}
		for _, k := range []string{"all_of", "any_of"} {
			if l, ok := m[k].([]any); ok {
				for _, x := range l {
					walk(x)
				}
			}
		}
		if n, has := m["not"]; has && anlTruthy(n) {
			walk(n)
		}
	}
	if w, ok := anlGet(p, "where").([]any); ok {
		for _, c := range w {
			walk(c)
		}
	}
	return set.keys
}

// anlGenerateBoundaryTests: boundary examples for every clause and numeric threshold. Expectations are the policy's CURRENT behaviour,
// to be confirmed.
func anlGenerateBoundaryTests(policy, optsIn any) map[string]any {
	o := optsIn
	if o == nil || anlIsUndef(o) {
		o = map[string]any{}
	}
	eps := anlToNumber(anlNN(anlGet(o, "epsilon"), 1))
	model := anlToModel(policy)
	cases := []any{}
	seen := map[string]bool{}
	add := func(name string, action map[string]any) {
		key := anlJSON(action)
		if seen[key] {
			return
		}
		seen[key] = true
		w := anlWitnessOf(model, action)
		c := map[string]any{"name": name, "action": action, "expect": w["decision"]}
		if id := w["winner"].(map[string]any)["id"]; id != nil {
			c["decidedBy"] = id
		}
		cases = append(cases, c)
	}
	for i, p := range model["predicates"].([]any) {
		r := anlAlwaysDenies(map[string]any{"predicates": []any{p}, "caveats": model["caveats"], "vetoes": model["vetoes"], "tighten": model["tighten"]}, nil, nil)
		base, _ := r["witness"].(map[string]any)
		if base == nil {
			r2 := anlAlwaysDenies(map[string]any{"predicates": []any{p}, "caveats": model["caveats"]}, nil, nil)
			base, _ = r2["witness"].(map[string]any)
		}
		if base == nil {
			continue
		}
		add(fmt.Sprintf("%s: minimal admitted action", anlPermitID(i)), base)
		for _, path := range anlParamPaths(p) {
			name := path[len("action.params."):]
			for _, t := range anlThresholdsOf(anlToModel(map[string]any{"predicates": []any{p}}), path) {
				tf := anlToNumber(t)
				for _, tv := range []struct {
					tag string
					v   any
				}{{"below", tf - eps}, {"at", t}, {"above", tf + eps}} {
					a := anlCopy(base)
					params, _ := base["params"].(map[string]any)
					np := anlCopy(params)
					if np == nil {
						np = map[string]any{}
					}
					np[name] = tv.v
					a["params"] = np
					add(fmt.Sprintf("%s: %s %s %s", anlPermitID(i), name, tv.tag, anlNumStr(tf)), a)
				}
			}
		}
		other := anlCopy(base)
		other["resource"] = anlJS(base["resource"]) + "/__other__"
		add(fmt.Sprintf("%s: unmentioned resource", anlPermitID(i)), other)
	}
	// a trigger per prohibition: an action some permit would allow and this prohibition stops
	permitOnly := anlCopy(model)
	permitOnly["vetoes"] = []any{}
	permitOnly["tighten"] = []any{}
	pr := anlProbesFor([]map[string]any{model}, nil)
	for _, v := range model["vetoes"].([]any) {
		v := v
		hits, _ := anlCollect(pr, func(rep *anlRep) bool {
			return anlDecide(permitOnly, rep) != "deny" && anlVetoApplies(v, anlContextOfAction(anlRepToAction(rep)))
		}, anlDefaultMaxCombinations, 1)
		if len(hits) > 0 {
			add(fmt.Sprintf("%s: trigger", anlJS(anlGet(v, "id"))), anlRepToAction(hits[0]))
		}
	}
	return anlPolicyTestsDoc(policy, cases)
}

// anlDecideAll is the decision of every case of a test document under `policy`.
func anlDecideAll(policy, doc any) []any {
	model := anlToModel(policy)
	out := []any{}
	for _, c := range anlReqList(anlGet(doc, "cases")) {
		out = append(out, anlDecideAction(model, anlGet(c, "action")))
	}
	return out
}
