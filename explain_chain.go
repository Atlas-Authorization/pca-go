package pca

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

func xpIsBudgetAlloc(cv any) bool {
	if !xpIsObj(cv) || xpGet(cv, "type") != "budget_alloc" {
		return false
	}
	f, ok := jsNum(xpGet(cv, "limit"))
	return ok && xpIsFin(xpGet(cv, "limit")) && f >= 0
}

// ExplainBudgetAllocNodes is the per-node budget subtree carried by a chain: one node per well-formed `budget_alloc` caveat, in
// delegation order. It reads the append-only caveat lineage and does not verify signatures (run VerifyChain first).
func ExplainBudgetAllocNodes(chain any) ([]any, error) {
	var out []any
	err := xpTry(func() { out = xpBudgetNodes(chain) })
	return out, err
}

func xpBudgetNodes(chain any) []any {
	out := []any{}
	cl, ok := chain.([]any)
	if !ok || len(cl) == 0 {
		return out
	}
	leafCvs, ok := xpRd(cl[len(cl)-1], "caveats").([]any)
	if !ok {
		return out
	}
	hop := 0
	for ci, cv := range leafCvs {
		for hop < len(cl)-1 {
			n := 0
			if l, ok := xpLength(xpRd(cl[hop], "caveats")).(json.Number); ok {
				n, _ = strconv.Atoi(string(l))
			}
			if n <= ci {
				hop++
			} else {
				break
			}
		}
		if !xpIsBudgetAlloc(cv) {
			continue
		}
		introducing := cl[hop]
		capID := xpRd(introducing, "id")
		if xpIsUndef(capID) {
			xpPanic("canonicalize: undefined member")
		}
		np, err := HashCanonical(map[string]any{"d": "atlas-pca/budget-node/v1", "cap": capID, "i": xpInt(ci)})
		if err != nil {
			xpPanic(err.Error())
		}
		node := map[string]any{"nodePath": np}
		xpPut(node, "capId", capID)
		xpPut(node, "holder", xpRd(introducing, "holder"))
		node["depth"] = xpInt(hop)
		node["caveatIndex"] = xpInt(ci)
		node["limit"] = cv.(map[string]any)["limit"]
		out = append(out, node)
	}
	return out
}

func xpHopNarrowed(isRoot bool, added []any) string {
	var bits []string
	for _, cv := range added {
		typ, rest := xpCaveatType(cv), xpCaveatRest(cv)
		switch {
		case typ == "envelope":
			np, ni := 0, 0
			if l, ok := rest.m["predicates"].([]any); ok {
				np = len(l)
			}
			if l, ok := rest.m["caveats"].([]any); ok {
				ni = len(l)
			}
			bits = append(bits, fmt.Sprintf("envelope (%d predicate(s), %d caveat(s))", np, ni))
		case xpIsBudgetAlloc(cv):
			bits = append(bits, "budget_alloc(B_sub="+xpN(cv.(map[string]any)["limit"])+")")
		default:
			if b := xpValueSummary(rest); b != "" {
				bits = append(bits, "+"+typ+"("+b+")")
			} else {
				bits = append(bits, "+"+typ)
			}
		}
	}
	if len(bits) == 0 {
		if isRoot {
			return "root grant (no caveats)"
		}
		return "rebind only (no new caveats)"
	}
	if isRoot {
		return "grants " + strings.Join(bits, ", ")
	}
	return "narrows: " + strings.Join(bits, ", ")
}

func xpExplainChainInner(chain any) map[string]any {
	safe, _ := chain.([]any)
	hops := []any{}
	for i, cap := range safe {
		if !xpTruthy(cap) {
			continue
		}
		isRoot := i == 0
		parentLen := 0
		if i > 0 && xpTruthy(safe[i-1]) {
			if pc, ok := xpGet(safe[i-1], "caveats").([]any); ok {
				parentLen = len(pc)
			}
		}
		own, _ := xpGet(cap, "caveats").([]any)
		var added []any
		if isRoot {
			added = own
		} else if len(own) >= parentLen {
			added = own[parentLen:]
		}
		var budgetCv any
		for _, cv := range added {
			if xpIsBudgetAlloc(cv) {
				budgetCv = cv
				break
			}
		}
		hop := map[string]any{"index": xpInt(i), "isRoot": isRoot}
		xpPut(hop, "issuer", xpGet(cap, "issuer"))
		xpPut(hop, "holder", xpGet(cap, "holder"))
		hop["issuerShort"] = xpShort(xpGet(cap, "issuer"))
		hop["holderShort"] = xpShort(xpGet(cap, "holder"))
		hop["alg"] = xpNN(xpGet(cap, "alg"), "ed25519")
		ac := make([]any, len(added))
		copy(ac, added)
		hop["addedCaveats"] = ac
		types := make([]any, len(added))
		for j, cv := range added {
			types[j] = xpCaveatType(cv)
		}
		hop["addedCaveatTypes"] = types
		hop["narrowed"] = xpClean(xpHopNarrowed(isRoot, added))
		if budgetCv != nil {
			hop["budgetAlloc"] = budgetCv.(map[string]any)["limit"]
		}
		hops = append(hops, hop)
	}
	var root, leaf any = xpUndef, xpUndef
	if len(safe) > 0 {
		root, leaf = safe[0], safe[len(safe)-1]
	}
	nodes := xpBudgetNodes(safe)
	summary := "empty chain (no authority)"
	if len(safe) > 0 {
		summary = fmt.Sprintf("%s (principal) delegated through %d hop(s) to the acting holder %s; %d budget node(s).",
			xpShort(xpOpt(root, "issuer")), len(safe)-1, xpShort(xpOpt(leaf, "holder")), len(nodes))
	}
	out := map[string]any{"kind": "chain", "depth": xpInt(len(safe)), "hops": hops}
	xpPut(out, "rootIssuer", xpOpt(root, "issuer"))
	xpPut(out, "leafHolder", xpOpt(leaf, "holder"))
	out["budgetNodes"] = nodes
	out["summary"] = summary
	return out
}

// ExplainChain renders a delegation chain as an ordered attenuation trace: issuer to holder per hop and what each hop narrowed.
// With opts.verify == true the chain is also checked (opts.expectedRootIssuer pins the root issuer); otherwise the trace shows
// only what the chain claims.
func ExplainChain(chain, opts any) (map[string]any, error) {
	var out map[string]any
	err := xpTry(func() {
		out = xpExplainChainInner(chain)
		if xpRd(opts, "verify") != true {
			return
		}
		ok, reason, hasReason := false, "chain is not an array", true
		if xpTry(func() {
			if cl, isList := chain.([]any); isList {
				exp := xpGet(opts, "expectedRootIssuer")
				es, have := exp.(string)
				if !xpIsUndef(exp) && exp != nil && !have {
					es, have = "\x00non-string", true // the reference compares as-is: a non-string never matches
				}
				why, vok := VerifyChain(cl, es, have)
				ok, reason, hasReason = vok, why, !vok
			}
		}) != nil {
			ok, reason, hasReason = false, "chain could not be verified", true
		}
		v := map[string]any{"ok": ok}
		if hasReason {
			v["reason"] = xpClean(reason)
		}
		out["verification"] = v
	})
	return out, err
}

// ExplainChainText renders a chain explanation.
func ExplainChainText(e map[string]any) (string, error) {
	var out string
	err := xpTry(func() {
		lines := []string{fmt.Sprintf("PCA delegation chain — %s hop(s) (attenuation trace)", xpStr(e["depth"]))}
		v := xpGet(e, "verification")
		switch {
		case xpIsUndef(v):
			lines = append(lines, "UNVERIFIED: this trace shows what the chain claims; no signature or link was checked.")
		case v.(map[string]any)["ok"] == true:
			lines = append(lines, "verified: signatures, links and caveat rules hold.")
		default:
			lines = append(lines, "NOT VALID: "+xpStr(xpNN(xpGet(v, "reason"), "the chain failed verification")))
		}
		lines = append(lines, xpStr(e["summary"]), "")
		for _, hi := range e["hops"].([]any) {
			h := hi.(map[string]any)
			tag := "deleg"
			if h["isRoot"] == true {
				tag = "root "
			}
			lines = append(lines, fmt.Sprintf("  #%s %s %s ──▶ %s   %s", xpStr(h["index"]), tag, xpStr(h["issuerShort"]), xpStr(h["holderShort"]), xpStr(h["narrowed"])))
		}
		if nodes := e["budgetNodes"].([]any); len(nodes) > 0 {
			ps := make([]string, len(nodes))
			for i, ni := range nodes {
				n := ni.(map[string]any)
				ps[i] = fmt.Sprintf("depth %s B_sub=%s", xpStr(n["depth"]), xpN(n["limit"]))
			}
			lines = append(lines, "", "  budget subtree: "+strings.Join(ps, " → "))
		}
		out = strings.Join(lines, "\n")
	})
	return out, err
}
