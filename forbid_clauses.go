package pca

import (
	"slices"
	"sort"
)

// Forbid-wins clause decision and its certificate (the policy half of forbid-certificate.go): any forbid matched denies, else no
// permit matched denies, else an escalate matched escalates, else allow. Order-independent for the decision; the named winner is
// deterministic (the most authoritative signer's forbid, ties by id). Total: a malformed policy or action is a deny naming `malformed`.

// MaxClauses is the most clauses one policy may carry (a bound on the certificate size).
const MaxClauses = 512

// ClausesError is "" when the clause list is well formed (distinct ids, known kinds, a predicate for each).
func ClausesError(clauses any) string {
	list, ok := clauses.([]any)
	if !ok {
		return "clauses must be an array"
	}
	if len(list) > MaxClauses {
		return "more than 512 clauses"
	}
	seen := map[string]bool{}
	for i, cv := range list {
		is := pInt(i).String()
		c, isObj := cv.(map[string]any)
		if !isObj {
			return "clauses[" + is + "] must be an object"
		}
		id, isStr := c["id"].(string)
		if !isStr || len(id) == 0 || len(utf16Units(id)) > 128 {
			return "clauses[" + is + "].id must be a string of 1..128 characters"
		}
		if seen[id] {
			return "clauses[" + is + "].id '" + id + "' is a duplicate"
		}
		seen[id] = true
		if k, isStr := c["kind"].(string); !isStr || (k != "permit" && k != "forbid" && k != "escalate") {
			return "clauses[" + is + "].kind must be permit, forbid or escalate"
		}
		if sg, has := c["signer"]; has {
			if s, isStr := sg.(string); !isStr || len(utf16Units(s)) > 256 {
				return "clauses[" + is + "].signer must be a string of at most 256 characters"
			}
		}
		if _, isObj := c["when"].(map[string]any); !isObj {
			return "clauses[" + is + "].when must be a predicate object"
		}
	}
	return ""
}

func clauseValue(c map[string]any, ctx map[string]any, b *regexBudget) string {
	if c["kind"] == "permit" {
		if predicateMatches(c["when"], ctx, b) {
			return "true"
		}
		return "false"
	}
	// veto polarity: a clean match is true; cannot-decide-but-the-veto-applies is unknown; a clean miss is false
	if !whenMatchesB(c["when"], ctx, b) {
		return "false"
	}
	if predicateMatches(c["when"], ctx, b) {
		return "true"
	}
	return "unknown"
}

func clauseRank(c map[string]any, precedence []string) int {
	if s, ok := c["signer"].(string); ok {
		if i := slices.Index(precedence, s); i >= 0 {
			return i
		}
	}
	return len(precedence) // an unlisted signer ranks last
}

func malformedDecision() map[string]any {
	return map[string]any{"decision": "deny", "witness": map[string]any{"winner": map[string]any{"kind": "malformed", "id": nil}, "shadowed": []any{}}, "values": []any{}}
}

// DecideClauses decides a clause list against an action context ({action: {verb, resource, params}, ...}). permitSigners, when non-nil
// (even empty), drops permits from any other signer. The result is {decision, witness: {winner: {kind, id}, shadowed}, values}.
func DecideClauses(clauses any, ctx any, precedence []string, permitSigners []string) (res map[string]any) {
	cn, _ := pNorm(clauses)
	xn, _ := pNorm(ctx)
	return decideClausesB(cn, xn, precedence, permitSigners, &regexBudget{})
}

func decideClausesB(clauses any, ctx any, precedence []string, permitSigners []string, b *regexBudget) (res map[string]any) {
	defer func() {
		if recover() != nil {
			res = malformedDecision()
		}
	}()
	if ClausesError(clauses) != "" {
		return malformedDecision()
	}
	cm, _ := ctx.(map[string]any)
	a, _ := cm["action"].(map[string]any)
	if !isString(a["verb"]) || !isString(a["resource"]) {
		return malformedDecision()
	}
	list := clauses.([]any)
	values := make([]any, len(list))
	var forbids, permits, escalates []map[string]any
	for i, cv := range list {
		c := cv.(map[string]any)
		kind := c["kind"].(string)
		active := kind != "permit" || permitSigners == nil
		if !active {
			if s, ok := c["signer"].(string); ok && slices.Contains(permitSigners, s) {
				active = true
			}
		}
		v := "false"
		if active {
			v = clauseValue(c, cm, b)
		}
		values[i] = map[string]any{"id": c["id"], "kind": kind, "value": v}
		if v != "false" {
			switch kind {
			case "forbid":
				forbids = append(forbids, c)
			case "permit":
				permits = append(permits, c)
			default:
				escalates = append(escalates, c)
			}
		}
	}
	sort.SliceStable(forbids, func(i, j int) bool {
		ri, rj := clauseRank(forbids[i], precedence), clauseRank(forbids[j], precedence)
		if ri != rj {
			return ri < rj
		}
		return utf16Less(forbids[i]["id"].(string), forbids[j]["id"].(string))
	})
	others := func(win map[string]any) []any {
		out := []any{}
		for _, group := range [][]map[string]any{forbids, permits, escalates} {
			for _, c := range group {
				if win == nil || c["id"] != win["id"] {
					out = append(out, c["id"])
				}
			}
		}
		return out
	}
	decide := func(decision, kind string, win map[string]any) map[string]any {
		var id any
		if win != nil {
			id = win["id"]
		}
		return map[string]any{"decision": decision, "witness": map[string]any{"winner": map[string]any{"kind": kind, "id": id}, "shadowed": others(win)}, "values": values}
	}
	switch {
	case len(forbids) > 0:
		return decide("deny", "forbid", forbids[0])
	case len(permits) == 0:
		return decide("deny", "none", nil)
	case len(escalates) > 0:
		return decide("escalate", "escalate", escalates[0])
	}
	return decide("allow", "permit", permits[0])
}

// Certify builds the canonical certificate for a decision.
func Certify(clauses any, ctx any, precedence []string, permitSigners []string) (map[string]any, error) {
	cn, _ := pNorm(clauses)
	xn, _ := pNorm(ctx)
	d := decideClausesB(cn, xn, precedence, permitSigners, &regexBudget{})
	byID := map[string]map[string]any{}
	if list, ok := cn.([]any); ok {
		for _, cv := range list {
			if c, isObj := cv.(map[string]any); isObj {
				if id, isStr := c["id"].(string); isStr {
					byID[id] = c
				}
			}
		}
	}
	rows := []any{}
	for _, vv := range d["values"].([]any) {
		v := vv.(map[string]any)
		row := map[string]any{"id": v["id"], "kind": v["kind"]}
		if sg := byID[v["id"].(string)]["signer"]; sg != nil {
			row["signer"] = sg
		}
		row["value"] = v["value"]
		rows = append(rows, row)
	}
	policy, err := HashCanonical(cn)
	if err != nil {
		return nil, err
	}
	action, err := HashCanonical(xn)
	if err != nil {
		return nil, err
	}
	w := d["witness"].(map[string]any)
	return map[string]any{"v": pInt(1), "kind": "forbid-wins", "policy": policy, "action": action, "decision": d["decision"], "winner": w["winner"],
		"shadowed": w["shadowed"], "clauses": rows}, nil
}

// CheckForbidCertificate recomputes the certificate from the clauses and the action; it must match byte for byte (canonical form).
func CheckForbidCertificate(cert any, clauses any, ctx any, precedence []string, permitSigners []string) (res map[string]any) {
	defer func() {
		if recover() != nil {
			res = map[string]any{"ok": false, "reason": "certificate check error (fail closed)"}
		}
	}()
	cn, _ := pNorm(clauses)
	certn, _ := pNorm(cert)
	if ClausesError(cn) != "" {
		return map[string]any{"ok": false, "reason": "malformed clauses"}
	}
	if !ForbidCertificateConsistent(certn, precedence) {
		return map[string]any{"ok": false, "reason": "certificate table does not entail its decision"}
	}
	again, err := Certify(cn, ctx, precedence, permitSigners)
	if err != nil {
		return map[string]any{"ok": false, "reason": "certificate check error (fail closed)"}
	}
	h1, e1 := HashCanonical(again)
	h2, e2 := HashCanonical(certn)
	if e1 != nil || e2 != nil {
		return map[string]any{"ok": false, "reason": "certificate check error (fail closed)"}
	}
	if h1 != h2 {
		return map[string]any{"ok": false, "reason": "certificate does not match the recomputed decision"}
	}
	return map[string]any{"ok": true}
}
