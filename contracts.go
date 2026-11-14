package pca

// Bounded safety-LTL behavioural contracts: an optional embedded prohibition constitution (`invariants`) plus temporal `clauses`
// (always, never, precedes, requires_prior, responds_within, and) over one shared, hash-chained monitor state. A contract without
// clauses behaves exactly like the prohibition monitor. Everything malformed, unknown or unresolvable fails closed; nothing here
// panics. Values and results are JSON shapes (see prohibitions.go).

import (
	"math"
	"strings"
)

const (
	ContractVersion       = 1
	ContractSigDomain     = "atlas-pca/contract/v1\x00"
	ContractMaxClauses    = 256
	ContractMaxClauseDeep = 16
)

// ValidateClause: the structural problems with a clause (empty = well formed); ids are collected into seen for global uniqueness.
func ValidateClause(cl any, seen map[string]bool, depth int) []string {
	if depth > ContractMaxClauseDeep {
		return []string{"clause nesting too deep"}
	}
	m, ok := cl.(map[string]any)
	if !ok {
		return []string{"clause not an object"}
	}
	id, isStr := m["id"].(string)
	if !isStr || id == "" {
		return []string{"<no id>: missing clause id"}
	}
	err := func(msg string) []string { return []string{id + ": " + msg} }
	if len(utf16Units(id)) > maxIDLen {
		return err("id too long")
	}
	if isForbiddenID(id) {
		return err("forbidden id")
	}
	if seen[id] {
		return err("duplicate id")
	}
	seen[id] = true
	kind, _ := m["kind"].(string)
	switch kind {
	case "always", "never":
		if e := ValidateWhen(m["p"], "p"); e != "" {
			return err(e)
		}
		return nil
	case "precedes", "requires_prior":
		if e := ValidateWhen(m["p"], "p"); e != "" {
			return err(e)
		}
		if e := ValidateWhen(m["q"], "q"); e != "" {
			return err(e)
		}
		return nil
	case "responds_within":
		if e := ValidateWhen(m["p"], "p"); e != "" {
			return err(e)
		}
		if e := ValidateWhen(m["q"], "q"); e != "" {
			return err(e)
		}
		if w := m["within"]; !pIsInteger(w) || pNum(w) < 1 || pNum(w) > MaxDeadline {
			return err("within must be an integer in [1, MAX_DEADLINE]")
		}
		return nil
	case "and":
		subs, isList := m["clauses"].([]any)
		if !isList || len(subs) == 0 {
			return err("and.clauses must be a non-empty array")
		}
		var out []string
		for _, sub := range subs {
			out = append(out, ValidateClause(sub, seen, depth+1)...)
		}
		return out
	}
	return err("unknown clause kind " + jsMemberString(m, "kind"))
}

func countClauses(cls []any, depth int) int {
	// bounded recursion: an absurdly deep nest is "too many" at once (ValidateClause then reports the depth)
	if depth > ContractMaxClauseDeep+1 {
		return ContractMaxClauses + 1
	}
	n := 0
	for _, cl := range cls {
		n++
		if m, ok := cl.(map[string]any); ok && m["kind"] == "and" {
			if sub, isList := m["clauses"].([]any); isList {
				n += countClauses(sub, depth+1)
			}
		}
	}
	return n
}

// ValidateContract: the structural problems with a contract (empty = well formed). Total.
func ValidateContract(c any) []string {
	m, ok := c.(map[string]any)
	if !ok {
		return []string{"contract not an object"}
	}
	out := []string{}
	if !pIsNum1(m["version"]) {
		out = append(out, "unsupported version "+pTextOf(m, "version"))
	}
	if !pNonEmptyStr(m["principal"]) {
		out = append(out, "principal missing")
	}
	ids := map[string]bool{}
	if iv, has := m["invariants"]; has {
		invs, isList := iv.([]any)
		if !isList {
			return append(out, "invariants not an array")
		}
		if len(invs) > MaxInvariants {
			out = append(out, "too many invariants")
		}
		for _, inv := range invs {
			out = append(out, ValidateInvariant(inv)...)
			if im, isObj := inv.(map[string]any); isObj {
				if id, isStr := im["id"].(string); isStr {
					if ids[id] {
						out = append(out, id+": duplicate id")
					}
					ids[id] = true
				}
			}
		}
	}
	if cv, has := m["clauses"]; has {
		cls, isList := cv.([]any)
		if !isList {
			return append(out, "clauses not an array")
		}
		if countClauses(cls, 1) > ContractMaxClauses {
			out = append(out, "too many clauses")
		}
		// clause ids must be globally unique AND disjoint from the constitution invariant ids (shared state keys)
		for _, cl := range cls {
			out = append(out, ValidateClause(cl, ids, 1)...)
		}
	}
	return out
}

// ContractID is the content address of a contract body.
func ContractID(c any) (string, error) {
	n, _ := pNorm(c)
	m, ok := n.(map[string]any)
	if !ok {
		return "", errMalformed
	}
	return HashCanonical(constitutionBody(m))
}

// SignContract signs a well-formed contract with the principal's Ed25519 seed (the principal key is c.principal).
func SignContract(c any, principalSeed []byte) (map[string]any, error) {
	n, _ := pNorm(c)
	if problems := ValidateContract(n); len(problems) > 0 {
		return nil, pError("signContract: " + strings.Join(problems, "; "))
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
	out["sig"] = b64.EncodeToString(kp.Sign(pDomainMessage(ContractSigDomain, id)))
	return out, nil
}

// VerifyContract: well formed, id matches the content, signature by expectedPrincipal ("" = the embedded principal). Never panics.
func VerifyContract(sc any, expectedPrincipal string) (res map[string]any) {
	defer func() {
		if recover() != nil {
			res = map[string]any{"ok": false, "reason": failClosedVerifyError}
		}
	}()
	n, _ := pNorm(sc)
	if problems := ValidateContract(n); len(problems) > 0 {
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
	if !isStr || !verifyB64u(m["principal"].(string), pDomainMessage(ContractSigDomain, id), sig) {
		return map[string]any{"ok": false, "reason": "bad signature"}
	}
	return map[string]any{"ok": true}
}

func embeddedConstitution(c map[string]any) map[string]any {
	invs, isList := c["invariants"].([]any)
	if !isList {
		invs = []any{}
	}
	return map[string]any{"version": pOne(), "principal": c["principal"], "invariants": invs}
}

// ContractFromConstitution is a contract with a constitution's invariants and no clauses.
func ContractFromConstitution(c map[string]any) map[string]any {
	return map[string]any{"version": pInt(ContractVersion), "principal": c["principal"], "invariants": c["invariants"], "clauses": []any{}}
}

// ---- clause evaluation -----------------------------------------------------------------------------------------------

type clauseTrans struct {
	ok                    bool
	reason                any
	rows                  []any
	latchSet, deadlineSet map[string]any // a nil deadlineSet value = discharged
}

func clauseRow(cl map[string]any, ok bool, reason any) map[string]any {
	row := map[string]any{"id": cl["id"], "kind": cl["kind"], "result": "violated"}
	if ok {
		row["result"] = "pass"
	}
	if pTruthy(reason) {
		row["reason"] = reason
	}
	return row
}

func clauseBase(cl map[string]any, ok bool, reason any) clauseTrans {
	t := clauseTrans{ok: ok, rows: []any{clauseRow(cl, ok, reason)}, latchSet: map[string]any{}, deadlineSet: map[string]any{}}
	if pTruthy(reason) {
		t.reason = reason
	}
	return t
}

func clauseDesc(cl map[string]any, def string) any {
	if d, has := cl["description"]; has && d != nil {
		return d
	}
	return def
}

// evalClause is the per-clause transition: the verdict plus the intended latch / deadline updates (applied only if the whole contract is ok).
func evalClause(cl map[string]any, ctx map[string]any, state map[string]any, now any, b *regexBudget) (t clauseTrans) {
	defer func() {
		if recover() != nil {
			t = clauseBase(cl, false, "clause evaluation error (fail closed)")
		}
	}()
	latched, _ := state["latched"].(map[string]any)
	deadlines, _ := state["deadlines"].(map[string]any)
	id := cl["id"].(string)
	switch cl["kind"] {
	case "always":
		if whenAffirmativeB(cl["p"], ctx, b) {
			return clauseBase(cl, true, nil)
		}
		return clauseBase(cl, false, clauseDesc(cl, "always-invariant violated (action does not satisfy p)"))
	case "never":
		if whenMatchesB(cl["p"], ctx, b) {
			return clauseBase(cl, false, clauseDesc(cl, "never-invariant violated (forbidden action)"))
		}
		return clauseBase(cl, true, nil)
	case "precedes", "requires_prior":
		isQ := whenMatchesB(cl["q"], ctx, b) // guarded action, conservative
		_, held := latched[id]
		ok := !isQ || held
		var reason any
		if !ok {
			reason = clauseDesc(cl, "precedence violated (prerequisite p not yet admitted before q)")
		}
		t := clauseBase(cl, ok, reason)
		// latch the prerequisite on an AFFIRMATIVE match (an ambiguous prerequisite must not count)
		if !held && whenAffirmativeB(cl["p"], ctx, b) {
			t.latchSet[id] = now
		}
		return t
	case "responds_within":
		violated := false
		var carried any
		if cur, open := deadlines[id]; open {
			if whenAffirmativeB(cl["q"], ctx, b) {
				carried = nil // any response discharges all open obligations
			} else if r := pNum(cur) - 1; r <= 0 {
				violated = true // window exhausted with no response => violation at this action
			} else {
				carried = jsNumber(r)
			}
		}
		if violated {
			row := clauseRow(cl, false, clauseDesc(cl, "bounded-liveness deadline missed (no q within "+jsValueString(cl["within"])+" actions of p)"))
			return clauseTrans{ok: false, reason: row["reason"], rows: []any{row}, latchSet: map[string]any{}, deadlineSet: map[string]any{}}
		}
		nxt := carried
		if whenMatchesB(cl["p"], ctx, b) {
			if nxt == nil {
				nxt = cl["within"]
			} else {
				nxt = jsNumber(math.Min(pNum(nxt), pNum(cl["within"])))
			}
		}
		return clauseTrans{ok: true, rows: []any{clauseRow(cl, true, nil)}, latchSet: map[string]any{}, deadlineSet: map[string]any{id: nxt}}
	case "and":
		out := clauseTrans{ok: true, rows: []any{}, latchSet: map[string]any{}, deadlineSet: map[string]any{}}
		var reason any
		for _, sub := range cl["clauses"].([]any) {
			r := evalClause(sub.(map[string]any), ctx, state, now, b)
			out.rows = append(out.rows, r.rows...)
			for k, v := range r.latchSet {
				out.latchSet[k] = v
			}
			for k, v := range r.deadlineSet {
				out.deadlineSet[k] = v
			}
			if !r.ok && out.ok {
				out.ok = false
				reason = r.reason
			}
		}
		if pTruthy(reason) {
			out.reason = reason
		}
		return out
	}
	return clauseBase(cl, false, "unknown clause kind (fail closed)")
}

// ---- the contract monitor --------------------------------------------------------------------------------------------

// CheckContract evaluates a whole contract (embedded constitution + temporal clauses) against one action WITHOUT advancing. Total, fail-closed.
func CheckContract(action, contract, state any) map[string]any {
	a, _ := pNorm(action)
	c, _ := pNorm(contract)
	s, _ := pNorm(state)
	return checkContractB(a, c, s, &regexBudget{})
}

func checkContractB(action, contract, state any, b *regexBudget) (res map[string]any) {
	fail := func(id, reason string) map[string]any {
		return map[string]any{"ok": false, "violated": []any{id}, "reasons": []any{id + ": " + reason},
			"evaluated": []any{map[string]any{"id": id, "kind": "structural", "result": "violated", "reason": reason}}}
	}
	defer func() {
		if recover() != nil {
			res = fail("<monitor>", "monitor error (fail closed)")
		}
	}()
	if cp := ValidateContract(contract); len(cp) > 0 {
		return fail("<contract>", cp[0])
	}
	if !actionOK(action) {
		return fail("<action>", "malformed action")
	}
	if sp := StateProblem(state); sp != "" {
		return fail("<state>", sp)
	}
	cm := contract.(map[string]any)
	evaluated := []any{}
	constitution := embeddedConstitution(cm)
	if len(constitution["invariants"].([]any)) > 0 {
		evaluated = append(evaluated, checkProhibitionsB(action, constitution, state, b)["evaluated"].([]any)...)
	}
	sm := state.(map[string]any)
	cls, _ := cm["clauses"].([]any)
	for _, cv := range cls {
		cl := cv.(map[string]any)
		t := func() (t clauseTrans) {
			defer func() {
				if recover() != nil {
					kind, has := cl["kind"]
					if !has {
						kind = "clause"
					}
					t = clauseTrans{rows: []any{map[string]any{"id": cl["id"], "kind": kind, "result": "violated", "reason": "clause evaluation error (fail closed)"}}}
				}
			}()
			return evalClause(cl, action.(map[string]any), sm, sm["now"], b)
		}()
		evaluated = append(evaluated, t.rows...)
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

// AdvanceContract checks the whole contract against one action and, iff it holds, advances the hash-chained monitor state. opts may
// carry now, expectedSeq and expectedStateDigest. Fail closed; next is the input state unless ok. Never panics.
func AdvanceContract(state, action, contract any, opts map[string]any) (res map[string]any) {
	s, _ := pNorm(state)
	a, _ := pNorm(action)
	c, _ := pNorm(contract)
	refuse := func(decidedBy string, r map[string]any, reason string) map[string]any {
		base := r
		if base == nil {
			base = checkContractB(a, c, s, &regexBudget{})
		}
		violated, reasons := base["violated"].([]any), base["reasons"].([]any)
		if reason != "" {
			nv := []any{}
			for _, v := range violated {
				if v != any("<state>") {
					nv = append(nv, v)
				}
			}
			violated = append(nv, "<state>")
			reasons = append(append([]any{}, reasons...), "<state>: "+reason)
		}
		return map[string]any{"ok": false, "violated": violated, "reasons": reasons, "evaluated": base["evaluated"], "next": s, "decidedBy": decidedBy}
	}
	defer func() {
		if recover() != nil {
			res = refuse("state", nil, "advance error (fail closed)")
		}
	}()
	sm, _ := s.(map[string]any)
	var now any
	if n, has := opts["now"]; has && n != nil {
		now, _ = pNorm(n)
	} else {
		now = sm["now"]
	}
	// CAS on the chain head FIRST: a rolled-back / stale state is refused before anything else
	if v, has := opts["expectedSeq"]; has {
		nv, _ := pNorm(v)
		if sm == nil || !jeq(sm["seq"], nv) {
			return refuse("state", nil, "stale state head (seq)")
		}
	}
	if v, has := opts["expectedStateDigest"]; has {
		if d := safeStr(func() (string, error) { return StateDigest(s) }); !isString(v) || v.(string) != d {
			return refuse("state", nil, "stale state head (digest)")
		}
	}
	verdict := checkContractB(a, c, s, &regexBudget{})
	if verdict["ok"] != true {
		structural := false
		for _, v := range verdict["violated"].([]any) {
			if vs := v.(string); strings.HasPrefix(vs, "<") && strings.HasSuffix(vs, ">") {
				structural = true
			}
		}
		out := copyObj(verdict)
		out["next"] = s
		out["decidedBy"] = "contract"
		if structural {
			out["decidedBy"] = "state"
		}
		return out
	}
	cm := c.(map[string]any)
	adv := advanceInner(a, embeddedConstitution(cm), s, now, &regexBudget{})
	if adv["ok"] != true {
		return refuse("state", verdict, "advance failed: "+adv["reason"].(string))
	}
	advState := adv["state"].(map[string]any)
	latched := copyObj(advState["latched"].(map[string]any))
	deadlines := map[string]any{}
	if d, ok := sm["deadlines"].(map[string]any); ok {
		deadlines = copyObj(d)
	}
	ob := &regexBudget{}
	cls, _ := cm["clauses"].([]any)
	for _, cv := range cls {
		t := evalClause(cv.(map[string]any), a.(map[string]any), sm, now, ob)
		for k, v := range t.latchSet {
			if _, done := latched[k]; !done {
				latched[k] = v
			}
		}
		for k, v := range t.deadlineSet {
			if v == nil {
				delete(deadlines, k)
			} else {
				deadlines[k] = v
			}
		}
	}
	nxt := copyObj(advState)
	nxt["latched"] = latched
	if len(deadlines) > 0 {
		nxt["deadlines"] = deadlines
	}
	if sp := StateProblem(nxt); sp != "" {
		return refuse("state", verdict, "resulting state invalid: "+sp)
	}
	out := copyObj(verdict)
	out["next"] = nxt
	out["decidedBy"] = "none"
	return out
}

// CheckAndAdvanceContract: allow = permitted AND contract ok; on allow the state advances. The contract monitor runs unconditionally.
func CheckAndAdvanceContract(permitted any, state, action, contract any, opts map[string]any) map[string]any {
	adv := AdvanceContract(state, action, contract, opts)
	p := permitted == true
	out := copyObj(adv)
	out["permitted"] = p
	if adv["ok"] != true {
		out["allow"] = false
		return out
	}
	if !p {
		s, _ := pNorm(state)
		return map[string]any{"ok": false, "violated": adv["violated"], "reasons": append(append([]any{}, adv["reasons"].([]any)...), "<permission>: not permitted"),
			"evaluated": adv["evaluated"], "next": s, "decidedBy": "contract", "allow": false, "permitted": p}
	}
	out["allow"] = true
	return out
}
