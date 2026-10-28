package pca

// K5 workflow (DAG) authorization, verification side: AdmitStep, BindPromises and PlanRootAuthorized. A line-by-line port of
// packages/pca/src/workflow.ts; replays packages/pca/conformance/workflow-vectors.json. Total and pure: no clock, no store, no
// I/O. Everything unknown, malformed, unsigned, out of order or unplanned DENIES; only a promised input with no domain constraint
// and a label the step marks "ask a human" ESCALATE. Inputs are decoded JSON (ParseJSONLenient); numbers must be safe integers.

import (
	"regexp"
)

const (
	k5WorkflowDomain  = "atlas-pca/workflow/v1\x00"
	k5WfReceiptDomain = "atlas-pca/wf-receipt/v1\x00"
	k5WfRef           = "atlas-pca/workflow-ref/v1"
	k5WrRef           = "atlas-pca/wf-receipt-ref/v1"
	k5ValDomain       = "atlas-pca/wf-value/v1"
)

// ---- strict helpers (shared with readside.go) ------------------------------------------------------------------------------

// k5Re is a TS regex; noProto emulates the (?!__proto__$) lookahead (RE2 has none). `$` without (?m) is end-of-text only.
type k5Re struct {
	re      *regexp.Regexp
	noProto bool
}

func (r k5Re) ok(x any) bool {
	s, isStr := x.(string)
	return isStr && !(r.noProto && s == "__proto__") && r.re.MatchString(s)
}

var (
	k5ID    = k5Re{regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`), true}
	k5Label = k5Re{regexp.MustCompile(`^[a-z0-9_.:-]{1,64}$`), true}
	k5Name  = k5Re{regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`), true}
	k5Unit  = k5Re{regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,16}$`), false}
)

func k5Obj(x any) (map[string]any, bool) { m, ok := x.(map[string]any); return m, ok }

// k5IsUint is Number.isSafeInteger(n) && n >= 0.
func k5IsUint(x any) bool {
	f, ok := jsNum(x)
	return ok && jsIsSafeInteger(x) && f >= 0
}

// k5F reads a number already validated by k5IsUint / k5IsScalar.
func k5F(x any) float64 { f, _ := jsNum(x); return f }

func k5IsB32(x any) bool {
	s, ok := x.(string)
	if !ok {
		return false
	}
	_, ok = DecodeB64uStrict(s, 32)
	return ok
}

func k5OnlyKeys(m map[string]any, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, has := m[k]; !has {
			return false
		}
	}
	return true
}

func k5NullOr(x any, ok func(any) bool) bool { return x == nil || ok(x) }

// k5SortedUnique: strictly ascending (bytewise; every member is ASCII) with every member matching re.
func k5SortedUnique(x any, re k5Re, max int) bool {
	l, ok := x.([]any)
	if !ok || len(l) > max {
		return false
	}
	for i, e := range l {
		if !re.ok(e) || (i > 0 && !(l[i-1].(string) < e.(string))) {
			return false
		}
	}
	return true
}

// k5Strs lists the strings of an already validated string array.
func k5Strs(x any) []string {
	l, _ := x.([]any)
	out := make([]string, 0, len(l))
	for _, e := range l {
		s, _ := e.(string)
		out = append(out, s)
	}
	return out
}

func k5Has(l []string, s string) bool {
	for _, e := range l {
		if e == s {
			return true
		}
	}
	return false
}

// k5EqNull is `a !== b` negated for values that are null or a string.
func k5EqNull(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	as, ok1 := a.(string)
	bs, ok2 := b.(string)
	return ok1 && ok2 && as == bs
}

func k5Hash(v any) string {
	h, ok := hashCanonicalV(v)
	if !ok {
		panic("k5: not canonical")
	}
	return h
}

// k5VerifyBody: sig is a canonical 64-byte base64url Ed25519 signature by signer over exactly domain || canonical(body).
func k5VerifyBody(domain string, body map[string]any, signer, sig any) bool {
	s, ok1 := signer.(string)
	g, ok2 := sig.(string)
	if !ok1 || !ok2 {
		return false
	}
	if _, ok := DecodeB64uStrict(g, 64); !ok {
		return false
	}
	return extSigned(s, domain, body, g)
}

// WorkflowValueDigest is the digest of a scalar as it appears in step receipts (never equal to a params digest).
func WorkflowValueDigest(v any) (string, bool) {
	return hashCanonicalV(map[string]any{"d": k5ValDomain, "v": v})
}

func k5IsScalar(v any) bool {
	switch v.(type) {
	case string, bool:
		return true
	}
	_, isNum := jsNum(v)
	return isNum && jsIsSafeInteger(v)
}

func k5IsScalarMap(x any) bool {
	m, ok := k5Obj(x)
	if !ok || len(m) > 32 {
		return false
	}
	for k, v := range m {
		if !k5Name.ok(k) || !k5IsScalar(v) {
			return false
		}
	}
	return true
}

// ---- validation ------------------------------------------------------------------------------------------------------------

func k5UintMap(x any, max int) bool {
	m, ok := k5Obj(x)
	if !ok || len(m) > max {
		return false
	}
	for k, v := range m {
		if !k5Name.ok(k) || !k5IsUint(v) {
			return false
		}
	}
	return true
}

func k5Id(x any) bool   { return k5ID.ok(x) }
func k5Nm(x any) bool   { return k5Name.ok(x) }
func k5Un(x any) bool   { return k5Unit.ok(x) }
func k5Sfx(x any) bool  { return k5IsB32(x) }
func k5Uint(x any) bool { return k5IsUint(x) }

func k5ValidStep(x any) bool {
	s, ok := k5Obj(x)
	if !ok || !k5OnlyKeys(s, "id", "verb", "resource", "params_digest", "deps", "sink", "deny_labels", "escalate_labels", "fresh_ms", "cost") {
		return false
	}
	return k5Id(s["id"]) && k3Str(s["verb"], 128) && k3Str(s["resource"], 512) && k5NullOr(s["params_digest"], k5Sfx) && k5SortedUnique(s["deps"], k5ID, 16) &&
		k5NullOr(s["sink"], k5Id) && k5SortedUnique(s["deny_labels"], k5Label, 16) && k5SortedUnique(s["escalate_labels"], k5Label, 16) &&
		k5NullOr(s["fresh_ms"], k5Uint) && k5UintMap(s["cost"], 8)
}

func k5ValidEdge(x any) bool {
	e, ok := k5Obj(x)
	if !ok || !k5OnlyKeys(e, "from", "to", "op", "unit", "deny_labels", "promise") {
		return false
	}
	f, ok1 := k5Obj(e["from"])
	t, ok2 := k5Obj(e["to"])
	if !ok1 || !ok2 || !k5OnlyKeys(f, "step", "field") || !k5Id(f["step"]) || !k5Nm(f["field"]) || !k5OnlyKeys(t, "step", "param") || !k5Id(t["step"]) || !k5Nm(t["param"]) {
		return false
	}
	op, _ := e["op"].(string)
	if op != "eq" && op != "le" && op != "ge" && op != "lt" && op != "gt" {
		return false
	}
	return k5NullOr(e["unit"], k5Un) && k5SortedUnique(e["deny_labels"], k5Label, 16) && k5NullOr(e["promise"], k5Id)
}

// k5ValidWorkflowBody checks the shape of the body only (no signature, no DAG semantics).
func k5ValidWorkflowBody(x any) bool {
	b, ok := k5Obj(x)
	if !ok || !k5OnlyKeys(b, "v", "id", "principal", "goal_digest", "plan_root", "issued_at", "expires_at", "steps", "edges", "budget") {
		return false
	}
	if f, isNum := jsNum(b["v"]); !isNum || f != 1 {
		return false
	}
	if !k5Id(b["id"]) || !k5IsB32(b["principal"]) || !k5NullOr(b["goal_digest"], k5Sfx) || !k5NullOr(b["plan_root"], k5Sfx) || !k5IsUint(b["issued_at"]) || !k5IsUint(b["expires_at"]) {
		return false
	}
	steps, ok := b["steps"].([]any)
	if !ok || len(steps) == 0 || len(steps) > 64 {
		return false
	}
	for _, s := range steps {
		if !k5ValidStep(s) {
			return false
		}
	}
	edges, ok := b["edges"].([]any)
	if !ok || len(edges) > 256 {
		return false
	}
	for _, e := range edges {
		if !k5ValidEdge(e) {
			return false
		}
	}
	bg, ok := k5Obj(b["budget"])
	if !ok || !k5OnlyKeys(bg, "max_steps", "caps") || !k5IsUint(bg["max_steps"]) || !k5UintMap(bg["caps"], 8) {
		return false
	}
	// every cost name must be capped: an uncapped cost is a budget that silently does not exist
	caps := bg["caps"].(map[string]any)
	for _, s := range steps {
		for name := range s.(map[string]any)["cost"].(map[string]any) {
			if _, has := caps[name]; !has {
				return false
			}
		}
	}
	return true
}

func k5StepsByID(b map[string]any) (map[string]map[string]any, bool) {
	ids := map[string]map[string]any{}
	for _, x := range b["steps"].([]any) {
		s := x.(map[string]any)
		id := s["id"].(string)
		if _, dup := ids[id]; dup {
			return ids, false
		}
		ids[id] = s
	}
	return ids, true
}

// k5DagError: unique ids, deps exist, acyclic, every edge runs from a (transitive) dependency. "" when sound.
func k5DagError(b map[string]any) string {
	ids, unique := k5StepsByID(b)
	if !unique {
		return "duplicate step id"
	}
	for id, s := range ids {
		for _, d := range k5Strs(s["deps"]) {
			if _, has := ids[d]; d == id || !has {
				return "bad dependency"
			}
		}
	}
	anc, ok := k5Ancestors(b)
	if !ok {
		return "cycle"
	}
	for _, x := range b["edges"].([]any) {
		e := x.(map[string]any)
		from := e["from"].(map[string]any)["step"].(string)
		to := e["to"].(map[string]any)["step"].(string)
		_, hasFrom := ids[from]
		_, hasTo := ids[to]
		if !hasFrom || !hasTo || !anc[to][from] {
			return "edge does not follow a dependency"
		}
	}
	return ""
}

// k5Ancestors maps a step id to the set of its transitive dependencies; ok is false on a cycle.
func k5Ancestors(b map[string]any) (map[string]map[string]bool, bool) {
	byID := map[string]map[string]any{}
	for _, x := range b["steps"].([]any) {
		s := x.(map[string]any)
		byID[s["id"].(string)] = s
	}
	out := map[string]map[string]bool{}
	state := map[string]int{}
	var visit func(id string) bool
	visit = func(id string) bool {
		if state[id] == 2 {
			return true
		}
		if state[id] == 1 {
			return false
		}
		state[id] = 1
		set := map[string]bool{}
		for _, d := range k5Strs(byID[id]["deps"]) {
			if !visit(d) {
				return false
			}
			set[d] = true
			for x := range out[d] {
				set[x] = true
			}
		}
		out[id] = set
		state[id] = 2
		return true
	}
	for id := range byID {
		if !visit(id) {
			return nil, false
		}
	}
	return out, true
}

// WorkflowDigest is the content address of a workflow body (what receipts cite as `wf`).
func WorkflowDigest(body map[string]any) (string, bool) {
	return hashCanonicalV(map[string]any{"d": k5WfRef, "w": body})
}

// WorkflowReceiptRef is the digest the next step receipt cites as `prev`.
func WorkflowReceiptRef(r map[string]any) (string, bool) {
	return hashCanonicalV(map[string]any{"d": k5WrRef, "r": r})
}

func k5ReceiptBody(r map[string]any) map[string]any {
	b, _ := extPick(r, "v", "wf", "step", "seq", "prev", "outcome", "params_digest", "outputs", "issued_at", "signer")
	return b
}

func k5ValidReceiptShape(x any) bool {
	r, ok := k5Obj(x)
	if !ok || !k5OnlyKeys(r, "v", "wf", "step", "seq", "prev", "outcome", "params_digest", "outputs", "issued_at", "signer", "sig") {
		return false
	}
	if f, isNum := jsNum(r["v"]); !isNum || f != 1 {
		return false
	}
	if !k5IsB32(r["wf"]) || !k5Id(r["step"]) || !k5IsUint(r["seq"]) || !k5NullOr(r["prev"], k5Sfx) || (k5F(r["seq"]) == 0) != (r["prev"] == nil) {
		return false
	}
	if oc, _ := r["outcome"].(string); oc != "ok" && oc != "failed" {
		return false
	}
	if _, isStr := r["sig"].(string); !isStr || !k5IsB32(r["params_digest"]) || !k5IsUint(r["issued_at"]) || !k5IsB32(r["signer"]) {
		return false
	}
	o, ok := k5Obj(r["outputs"])
	if !ok || len(o) > 32 {
		return false
	}
	for k, x := range o {
		v, ok := k5Obj(x)
		if !k5Name.ok(k) || !ok || !k5OnlyKeys(v, "digest", "num", "unit", "labels") || !k5IsB32(v["digest"]) || !k5NullOr(v["num"], k5Uint) || !k5NullOr(v["unit"], k5Un) || !k5SortedUnique(v["labels"], k5Label, 16) {
			return false
		}
	}
	return true
}

// ---- admission -------------------------------------------------------------------------------------------------------------

// WfResult is an admission result. Code and Step are "" for null; At is -1 for null; Pending lists edge indexes whose source
// receipt does not exist yet (never nil).
type WfResult struct {
	Decision string // allow | deny | escalate
	Code     string
	Step     string
	At       int
	Pending  []int
}

// AdmitInput: Workflow, Receipts and Request are decoded JSON values. Principal is the key the verifier pinned (a key named inside
// the workflow is never trusted) and RsSigner the resource-server key pinned for step receipts.
type AdmitInput struct {
	Workflow  any
	Principal string
	RsSigner  string
	Receipts  any
	Now       int64
	Request   any
}

func k5Res(decision, code, step string, at int, pending []int) WfResult {
	if pending == nil {
		pending = []int{}
	}
	return WfResult{decision, code, step, at, pending}
}

func k5Deny(code, step string, at int) WfResult { return k5Res("deny", code, step, at, nil) }

// PlanRootAuthorized: is root the Merkle plan root this signed, unexpired, pinned-principal workflow authorizes?
func PlanRootAuthorized(workflow any, principal string, now int64, root string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	w, isObj := k5Obj(workflow)
	if !isObj || !k5ValidWorkflowBody(w["body"]) {
		return false
	}
	b := w["body"].(map[string]any)
	pr, _ := b["plan_root"].(string)
	return k5DagError(b) == "" && b["principal"] == principal && k5VerifyBody(k5WorkflowDomain, b, principal, w["sig"]) &&
		float64(now) >= k5F(b["issued_at"]) && float64(now) < k5F(b["expires_at"]) && b["plan_root"] != nil && pr == root
}

func k5ValidRequest(x any) bool {
	r, ok := k5Obj(x)
	if !ok || !k5OnlyKeys(r, "step", "verb", "resource", "params", "units", "goal_digest", "plan_root") {
		return false
	}
	if !k5Id(r["step"]) || !k3Str(r["verb"], 128) || !k3Str(r["resource"], 512) || !k5IsScalarMap(r["params"]) {
		return false
	}
	u, ok := k5Obj(r["units"])
	if !ok {
		return false
	}
	for k, v := range u {
		if !k5Name.ok(k) || !k5Un(v) {
			return false
		}
	}
	return k5NullOr(r["goal_digest"], k5Sfx) && k5NullOr(r["plan_root"], k5Sfx)
}

// k5ReceiptError checks the receipt chain against the workflow. Returns the offending index, or -1.
func k5ReceiptError(w map[string]any, rsSigner string, receipts []any, now int64) int {
	wd, _ := WorkflowDigest(w)
	byID, _ := k5StepsByID(w)
	index := map[string]int{}
	edges := w["edges"].([]any)
	var prev map[string]any
	for i, x := range receipts {
		if !k5ValidReceiptShape(x) {
			return i
		}
		r := x.(map[string]any)
		if r["signer"] != rsSigner || r["wf"] != wd || k5F(r["seq"]) != float64(i) || k5F(r["issued_at"]) > float64(now) {
			return i
		}
		step := r["step"].(string)
		if _, has := byID[step]; !has {
			return i
		}
		if _, dup := index[step]; dup {
			return i
		}
		if prev == nil {
			if r["prev"] != nil {
				return i
			}
		} else if ref, ok := WorkflowReceiptRef(prev); !ok || r["prev"] != ref {
			return i
		}
		if !k5VerifyBody(k5WfReceiptDomain, k5ReceiptBody(r), rsSigner, r["sig"]) {
			return i
		}
		// a receipt may precede one of its dependencies' receipts only when every edge from that dependency is a declared promise
		for _, d := range k5Strs(byID[step]["deps"]) {
			if _, done := index[d]; done {
				continue
			}
			n := 0
			for _, ex := range edges {
				e := ex.(map[string]any)
				if e["from"].(map[string]any)["step"] == d && e["to"].(map[string]any)["step"] == step {
					n++
					if e["promise"] == nil {
						return i
					}
				}
			}
			if n == 0 {
				return i
			}
		}
		index[step] = i
		prev = r
	}
	return -1
}

func k5Evaluate(inp AdmitInput, bind bool) WfResult {
	sw, ok := k5Obj(inp.Workflow)
	receipts, isArr := inp.Receipts.([]any)
	if !ok || !k5OnlyKeys(sw, "body", "sig") || !k5ValidWorkflowBody(sw["body"]) || !k5ValidRequest(inp.Request) || !isArr || !k5IsB32(inp.Principal) || !k5IsB32(inp.RsSigner) || inp.Now < 0 {
		return k5Deny("bad_workflow", "", -1)
	}
	w := sw["body"].(map[string]any)
	q := inp.Request.(map[string]any)
	qs := q["step"].(string)
	if k5DagError(w) != "" {
		return k5Deny("bad_dag", qs, -1)
	}
	if w["principal"] != inp.Principal || !k5VerifyBody(k5WorkflowDomain, w, inp.Principal, sw["sig"]) {
		return k5Deny("bad_signature", qs, -1)
	}
	now := float64(inp.Now)
	if now < k5F(w["issued_at"]) {
		return k5Deny("not_yet", qs, -1)
	}
	if now >= k5F(w["expires_at"]) {
		return k5Deny("expired", qs, -1)
	}
	if !k5EqNull(q["goal_digest"], w["goal_digest"]) {
		return k5Deny("goal_mismatch", qs, -1)
	}
	if !k5EqNull(q["plan_root"], w["plan_root"]) {
		return k5Deny("plan_root_mismatch", qs, -1)
	}
	if at := k5ReceiptError(w, inp.RsSigner, receipts, inp.Now); at >= 0 {
		return k5Deny("bad_receipt", qs, at)
	}
	rec := map[string]map[string]any{}
	for _, x := range receipts {
		r := x.(map[string]any)
		rec[r["step"].(string)] = r
	}
	byID, _ := k5StepsByID(w)
	step, planned := byID[qs]
	if !planned {
		return k5Deny("unplanned_step", qs, -1)
	}
	if step["verb"] != q["verb"] || step["resource"] != q["resource"] {
		return k5Deny("step_mismatch", qs, -1)
	}
	pd := k5Hash(q["params"])
	if step["params_digest"] != nil && step["params_digest"] != pd {
		return k5Deny("params_mismatch", qs, -1)
	}
	mine := rec[qs]
	budget := w["budget"].(map[string]any)
	if bind {
		if mine == nil || mine["params_digest"] != pd {
			return k5Deny("params_mismatch", qs, -1)
		}
	} else {
		if mine != nil {
			return k5Deny("already_done", qs, -1)
		}
		if float64(len(receipts)+1) > k5F(budget["max_steps"]) {
			return k5Deny("budget_exceeded", qs, -1)
		}
		for name, cap := range budget["caps"].(map[string]any) {
			spent := 0.0
			for _, x := range receipts {
				if c, has := byID[x.(map[string]any)["step"].(string)]["cost"].(map[string]any)[name]; has {
					spent += k5F(c)
				}
			}
			if c, has := step["cost"].(map[string]any)[name]; has {
				spent += k5F(c)
			}
			if spent > k5F(cap) {
				return k5Deny("budget_exceeded", qs, -1)
			}
		}
	}
	edges := w["edges"].([]any)
	edgeAt := func(i int) map[string]any { return edges[i].(map[string]any) }
	// dependencies
	pending := []int{}
	unconstrained := false
	for _, d := range k5Strs(step["deps"]) {
		dr := rec[d]
		if dr == nil {
			n := 0
			for i := range edges {
				e := edgeAt(i)
				if e["from"].(map[string]any)["step"] == d && e["to"].(map[string]any)["step"] == qs {
					n++
					if e["promise"] == nil {
						unconstrained = true
					}
				}
			}
			if bind || n == 0 {
				return k5Deny("deps_unmet", qs, -1)
			}
			continue
		}
		if dr["outcome"] != "ok" {
			return k5Deny("dep_failed", qs, -1)
		}
		if step["fresh_ms"] != nil && now-k5F(dr["issued_at"]) > k5F(step["fresh_ms"]) {
			return k5Deny("stale_dep", qs, -1)
		}
	}
	// edge constraints
	for i := range edges {
		e := edgeAt(i)
		if e["to"].(map[string]any)["step"] != qs {
			continue
		}
		src := rec[e["from"].(map[string]any)["step"].(string)]
		if src == nil {
			pending = append(pending, i)
			continue
		}
		out, hasOut := src["outputs"].(map[string]any)[e["from"].(map[string]any)["field"].(string)].(map[string]any)
		param := e["to"].(map[string]any)["param"].(string)
		val, hasVal := q["params"].(map[string]any)[param]
		if !hasOut || !hasVal {
			return k5Deny("edge_missing", qs, i)
		}
		if !k5EqNull(out["unit"], q["units"].(map[string]any)[param]) || !k5EqNull(out["unit"], e["unit"]) {
			return k5Deny("edge_unit", qs, i)
		}
		if e["op"] == "eq" {
			vd, ok := WorkflowValueDigest(val)
			if !ok || vd != out["digest"] {
				return k5Deny("edge_digest", qs, i)
			}
		} else {
			vf, isNum := jsNum(val)
			if !isNum || out["num"] == nil {
				return k5Deny("edge_value", qs, i)
			}
			nf := k5F(out["num"])
			var holds bool
			switch e["op"] {
			case "le":
				holds = vf <= nf
			case "ge":
				holds = vf >= nf
			case "lt":
				holds = vf < nf
			default:
				holds = vf > nf
			}
			if !holds {
				return k5Deny("edge_relation", qs, i)
			}
		}
		deny := k5Strs(e["deny_labels"])
		for _, l := range k5Strs(out["labels"]) {
			if k5Has(deny, l) {
				return k5Deny("taint_flow", qs, i)
			}
		}
	}
	if bind && len(pending) > 0 {
		return k5Deny("deps_unmet", qs, -1)
	}
	// taint across the DAG: every label any executed ancestor produced
	anc, _ := k5Ancestors(w)
	inherited := map[string]bool{}
	for a := range anc[qs] {
		if r := rec[a]; r != nil {
			for _, o := range r["outputs"].(map[string]any) {
				for _, l := range k5Strs(o.(map[string]any)["labels"]) {
					inherited[l] = true
				}
			}
		}
	}
	for _, l := range k5Strs(step["deny_labels"]) {
		if inherited[l] {
			return k5Deny("taint_flow", qs, -1)
		}
	}
	if unconstrained {
		return k5Res("escalate", "pipeline_unconstrained", qs, -1, nil)
	}
	for _, l := range k5Strs(step["escalate_labels"]) {
		if inherited[l] {
			return k5Res("escalate", "taint_escalate", qs, -1, nil)
		}
	}
	return k5Res("allow", "", qs, -1, pending)
}

func k5Total(inp AdmitInput, bind bool) (res WfResult) {
	defer func() {
		if recover() != nil {
			res = k5Deny("bad_workflow", "", -1)
		}
	}()
	return k5Evaluate(inp, bind)
}

// AdmitStep admits ONE step of the committed workflow, or denies / escalates. Never panics.
func AdmitStep(inp AdmitInput) WfResult { return k5Total(inp, false) }

// BindPromises is post-hoc promise binding: the step already has its receipt; its params are re-checked against every edge now
// that all of its dependencies' receipts exist. A pipelined step whose promise turns out wrong is a violation. Never panics.
func BindPromises(inp AdmitInput) WfResult { return k5Total(inp, true) }
