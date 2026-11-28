package pca

// Wallet-side layered intent lattice and quorum-signed layer approvals: ceiling admitters, owner risk, layer cell sets and
// k-of-n approvals of a shared-layer widening.

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
)

const ixLayerApprovalDomain = "atlas-pca/intent-layer-approval/v1\x00"

var ixLayerCeilings = []string{"org", "site", "std"}

// ixCeilingAdmitters compiles ceiling layers into admitters. Absent = no ceiling; a ceiling present as null or not an object is malformed.
func ixCeilingAdmitters(layers any) map[string]*IntentAdmitter {
	out := map[string]*IntentAdmitter{}
	lm, _ := layers.(map[string]any)
	for _, k := range ixLayerCeilings {
		l, present := lm[k]
		if !present {
			out[k] = nil
			continue
		}
		if _, ok := l.(map[string]any); !ok {
			ixFail("ceilingAdmitters: the %s ceiling is malformed (null or not an object)", k)
		}
		out[k] = ixAdmitter(l)
	}
	return out
}

// ixCeilingOf is the first ceiling that excludes the outcome (nil when every ceiling admits it).
func ixCeilingOf(c map[string]*IntentAdmitter, vs, o map[string]any) any {
	for _, k := range ixLayerCeilings {
		if a := c[k]; a != nil && !a.admits(vs, o) {
			return k
		}
	}
	return nil
}

func ixCellKeyJoin(cell any) string {
	parts := []string{}
	for _, i := range ixL(cell) {
		parts = append(parts, jsValueString(i))
	}
	return strings.Join(parts, ",")
}

func ixLayerKey(c map[string]any) string {
	return jsValueString(c["verb"]) + "|" + ixCellKeyJoin(c["cell"])
}

// ixAssertAskable: a question may only be about a cell of U_k (inside every ceiling); fails otherwise.
func ixAssertAskable(view, c map[string]any) {
	key := ixLayerKey(c)
	for _, u := range ixL(ixReq(view, "uncertain")) {
		if ixLayerKey(ixM(u)) == key {
			return
		}
	}
	ixFail("layers: cell %s is not an uncertain cell inside every ceiling (never a question)", key)
}

// ixOwnerRisk is the layer owner's own risk measure of a set of cells: sum of mu(c) (1 - a(c)) E[h | c].
func ixOwnerRisk(omega map[string]any, cells []any, acceptability func(vs, o map[string]any) float64) float64 {
	r := 0.0
	by := map[string]map[string]any{}
	for _, v := range ixL(omega["verbs"]) {
		by[ixS(ixM(v)["verb"])] = ixM(v)
	}
	for _, cv := range cells {
		c := ixM(cv)
		vs := by[ixS(c["verb"])]
		if vs == nil {
			continue
		}
		mass, harm := ixCellStats(vs, ixL(c["cell"]), ixDefaultHarm)
		r += float64(mass * (1 - acceptability(vs, ixCellRep(vs, ixL(c["cell"])))) * harm)
	}
	return r
}

// ixLayerCells is every cell of the outcome space an admitter admits.
func ixLayerCells(omega map[string]any, a *IntentAdmitter) []any {
	out := []any{}
	for _, vv := range ixL(omega["verbs"]) {
		vs := ixM(vv)
		n := int(ixVerbCellCount(vs))
		for f := 0; f < n; f++ {
			cell := ixDecodeCell(vs, float64(f))
			if a.admits(vs, ixCellRep(vs, cell)) {
				out = append(out, map[string]any{"verb": vs["verb"], "cell": cell})
			}
		}
	}
	return out
}

func ixCellKeyOf(omega, c map[string]any) string {
	for _, v := range ixL(omega["verbs"]) {
		vs := ixM(v)
		if vs["verb"] == c["verb"] {
			return jsValueString(c["verb"]) + "|" + jsValueString(ixEncodeCell(vs, ixL(c["cell"])))
		}
	}
	return jsValueString(c["verb"]) + "|" + ixCellKeyJoin(c["cell"])
}

// ---- quorum-signed layer approvals ----

var ixStatementKeys = []string{"layer", "session", "seq", "map_digest", "prev"}

// ixStatementOf is the approval statement of a; an absent member stays absent (undefined).
func ixStatementOf(a any) map[string]any {
	s := map[string]any{"v": 1.0, "kind": "pca-intent-layer-approval"}
	m, _ := a.(map[string]any)
	for _, k := range ixStatementKeys {
		if v, ok := m[k]; ok {
			s[k] = v
		}
	}
	return s
}

// ixStrictCanon is the strict canonical form of a JSON tree (numbers as their shortest decimal text).
func ixStrictCanon(v any) ([]byte, bool) {
	var conv func(v any) any
	conv = func(v any) any {
		switch t := v.(type) {
		case float64:
			return jsNumber(t)
		case map[string]any:
			m := make(map[string]any, len(t))
			for k, x := range t {
				m[k] = conv(x)
			}
			return m
		case []any:
			a := make([]any, len(t))
			for i, x := range t {
				a[i] = conv(x)
			}
			return a
		}
		return v
	}
	b, err := canonBytes(conv(v))
	return b, err == nil
}

func ixApprovalMessage(s map[string]any) ([]byte, bool) {
	for _, k := range ixStatementKeys {
		if _, ok := s[k]; !ok {
			return nil, false
		}
	}
	b, ok := ixStrictCanon(ixStatementOf(s))
	if !ok {
		return nil, false
	}
	return append([]byte(ixLayerApprovalDomain), b...), true
}

func ixSignLayerApproval(s map[string]any, seedB64 string) map[string]any {
	seed, ok := DecodeB64uStrict(seedB64, 32)
	if !ok {
		ixFail("secret key must be a 32-byte seed")
	}
	st := ixStatementOf(s)
	msg, ok := ixApprovalMessage(st)
	if !ok {
		ixFail("approval statement is not canonicalizable")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	st["signer"] = base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	st["sig"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, msg))
	return st
}

func ixQuorumFail(reason string) map[string]any {
	return map[string]any{"ok": false, "signers": []any{}, "ignored": []any{map[string]any{"index": -1.0, "reason": reason}}}
}

// ixVerifyQuorumApprovals: an approval counts iff its signer is a member, it is that member's first, its statement equals
// expected field by field and its signature verifies; the rule is the multi-principal one over member keys.
func ixVerifyQuorumApprovals(approvalsV, membersV, rule, expected any) map[string]any {
	approvals, ok1 := approvalsV.([]any)
	members, ok2 := membersV.([]any)
	_, em := expected.(map[string]any)
	_, el := expected.([]any)
	if !ok1 || !ok2 || !(em || el) {
		return ixQuorumFail("approvals and members must be arrays and expected an object")
	}
	refs := make([]string, len(members))
	seen := map[string]bool{}
	good := true
	for i, m := range members {
		s, ok := m.(string)
		if !ok || seen[s] {
			good = false
			break
		}
		seen[s] = true
		refs[i] = s
		if _, ok := DecodeB64uStrict(s, 32); !ok {
			good = false
			break
		}
	}
	if !good {
		return ixQuorumFail("members must be distinct 32-byte keys")
	}
	var n map[string]any
	if r, err := ixTry(func() any { return ixNormalizeRule(rule, refs) }); err != nil {
		return ixQuorumFail(err.Error())
	} else {
		n = r.(map[string]any)
	}
	want := ixStatementOf(expected)
	counted := map[string]bool{}
	ignored := []any{}
	ign := func(i int, reason string) {
		ignored = append(ignored, map[string]any{"index": float64(i), "reason": reason})
	}
	for i, av := range approvals {
		a, isMap := av.(map[string]any)
		_, isList := av.([]any)
		if !isMap && !isList {
			ign(i, "not an object")
			continue
		}
		signer, isStr := a["signer"].(string)
		if !isStr || !seen[signer] {
			ign(i, "signer is not a member")
			continue
		}
		if counted[signer] {
			ign(i, "second approval from the same member")
			continue
		}
		st := ixStatementOf(a)
		same := a["v"] == 1.0 && a["kind"] == "pca-intent-layer-approval"
		for k := range want {
			x, xo := st[k]
			y, yo := want[k]
			if xo != yo || (xo && !jsStrictEq(x, y)) {
				same = false
			}
		}
		for _, k := range ixStatementKeys {
			if _, ok := want[k]; !ok {
				if _, ok := st[k]; ok {
					same = false
				}
			}
		}
		if !same {
			ign(i, "approval is for another (layer, session, seq, map_digest, prev)")
			continue
		}
		okSig := false
		if sig, ok := a["sig"].(string); ok {
			if msg, ok := ixApprovalMessage(st); ok {
				okSig = verifyB64u(signer, msg, sig)
			}
		}
		if !okSig {
			ign(i, "bad signature")
			continue
		}
		counted[signer] = true
	}
	signers := []any{}
	ins := make([]any, len(refs))
	for i, m := range refs {
		ins[i] = counted[m]
		if counted[m] {
			signers = append(signers, m)
		}
	}
	return map[string]any{"ok": ixRuleAdmits(n, ins), "signers": signers, "ignored": ignored}
}

// IntentCommonRefinement is the union of several outcome spaces (numeric cuts and categorical values merged; domains must agree).
func IntentCommonRefinement(omegas []any) (map[string]any, error) {
	r, err := ixTry(func() any { return ixCommonRefinement(omegas) })
	if err != nil {
		return nil, err
	}
	return r.(map[string]any), nil
}

// IntentVerifyQuorumApprovals counts the valid, distinct member approvals of a shared-layer widening and applies the rule.
func IntentVerifyQuorumApprovals(approvals, members, rule, expected any) map[string]any {
	return ixVerifyQuorumApprovals(approvals, members, rule, expected)
}
