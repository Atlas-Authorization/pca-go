package pca

import (
	"errors"
	"sort"
)

// Small public helpers of the intent layer under the reference's names (verb space lookup, trajectory lift, state capture, the
// compiler-panel convenience and the profile usability check).

// IntentVsOf finds the verb space of an outcome in omega ({verbs: [...]}), or nil when the outcome's verb has none.
func IntentVsOf(omega, outcome map[string]any) map[string]any {
	for _, v := range ixL(omega["verbs"]) {
		if vm, ok := v.(map[string]any); ok && vm["verb"] == outcome["verb"] {
			return vm
		}
	}
	return nil
}

// IntentLiftedCell is the per-dimension cell of lift(xi, omega, t): the verb space and the cell of outcome o in omegaTilde, or ok
// false when it lies outside it (fail closed).
func IntentLiftedCell(omegaTilde, o map[string]any) (vs map[string]any, cell []any, ok bool) {
	vs = IntentVsOf(omegaTilde, o)
	if vs == nil {
		return nil, nil, false
	}
	cell = ixCellOf(vs, o)
	if cell == nil {
		return nil, nil, false
	}
	return vs, cell, true
}

// IntentCaptureState reads every monitored variable through its reader (in UTF-8 key order) and snapshots it; call it before and
// after an action. A reader that fails aborts the capture with its error.
func IntentCaptureState(readers map[string]func() (any, error), keepValues bool) (map[string]any, error) {
	keys := make([]string, 0, len(readers))
	for k := range readers {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return compareUtf8(keys[i], keys[j]) < 0 })
	values := map[string]any{}
	for _, k := range keys {
		v, err := readers[k]()
		if err != nil {
			return nil, err
		}
		values[k] = v
	}
	return ixSnapshotState(values, keepValues), nil
}

// IntentCompileAndCompare runs the compiler panel over input and analyses the disagreement; the input's slots (when present) are
// handed to the analysis. opts are the DisagreementOptions.
func IntentCompileAndCompare(input map[string]any, compilers []IntentCompiler, opts map[string]any) map[string]any {
	o := map[string]any{}
	for k, v := range opts {
		if k != "slots" {
			o[k] = v
		}
	}
	if s, has := input["slots"]; has && s != nil {
		o["slots"] = s
	}
	return ixAnalyzeDisagreement(IntentRunCompilers(input, compilers), o)
}

// IntentProfileUsable is {ok: true} when the profile verifies, has not expired at now and is not revoked: its revocation epoch
// (same format and bound as the session one, scoped to the profile id) must show the profile version unrevoked and, with last
// (the tracked previous epoch), extend it append-only. pin is the PQ pin policy for the profile signature and the epoch.
func IntentProfileUsable(p map[string]any, now, maxAgeMs any, revocation any, last any, lastP bool, pin map[string]string) map[string]any {
	if v := ixVerifyIntentProfile(p, pinAny(pin)); v["ok"] != true {
		return v
	}
	if !(finite(ixF(now)) && finite(ixF(p["expires_at"])) && ixF(now) < ixF(p["expires_at"])) {
		return map[string]any{"ok": false, "reason": "the profile has expired"}
	}
	authority := p["owner"]
	if rv, isObj := p["revocation"].(map[string]any); isObj {
		if k, has := rv["key"]; has {
			authority = k
		}
	}
	id := ixS(p["profile_id"])
	r := checkScopedRevocation(revocation, id, ProfileRevocationScope(id), authority, []any{profileRevocationID(id, ixF(p["version"]))}, now, maxAgeMs, last, lastP, pin)
	if r != "" {
		return map[string]any{"ok": false, "reason": "profile revocation: " + r}
	}
	return map[string]any{"ok": true}
}

func pinAny(pin map[string]string) any {
	if pin == nil {
		return nil
	}
	m := make(map[string]any, len(pin))
	for k, v := range pin {
		m[k] = v
	}
	return map[string]any{"pqPins": m}
}

// IntentSignedIntentRequired signs the site's pca-intent-required body for a visited uncertain cell (IntentRequiredBody over i, then
// SignIntentRequired).
func IntentSignedIntentRequired(i map[string]any, kid string, site *KeyPair, suite *SuiteOpts) (map[string]any, error) {
	return SignIntentRequired(IntentRequiredBody(i), kid, site, suite)
}

// IntentWalletCheckIntentRequired is the WALLET's check of an intent_required (straight from the site or relayed by the agent): the
// site signature under its discovery keys, the expiry, the session and map, and the CELL, which the wallet re-derives from its own
// omegaTilde and the lifted action. Any disagreement refuses the question (nothing is asked). On success the result carries
// {ok: true, vs, cell}.
func IntentWalletCheckIntentRequired(body, keys, now any, session, mapDigest string, omegaTilde, lifted, pcactn map[string]any) map[string]any {
	no := func(r string) map[string]any { return map[string]any{"ok": false, "reason": r} }
	if v := WalletVerifyIntentRequired(body, keys, now); v["ok"] != true {
		return v
	}
	b := body.(map[string]any)
	if b["session"] != session || b["map_digest"] != mapDigest {
		return no("the question is for another session or map")
	}
	pd, err := PCActnDigest(pcactn)
	act, _ := pcactn["action"].(map[string]any)
	if err != nil || b["pcactn_digest"] != pd || b["action_digest"] != IntentActionDigest(act) {
		return no("the question is about another action")
	}
	vs := IntentVsOf(omegaTilde, lifted)
	var mine []any
	if vs != nil {
		mine = ixCellOf(vs, lifted)
	}
	cell, _ := b["cell"].(map[string]any)
	if vs == nil || mine == nil || cell["verb"] != vs["verb"] {
		return no("the wallet cannot place the action in Ω̃")
	}
	theirs, _ := ixCellFromCoords(vs, cell["coords"]).([]any)
	if theirs == nil || len(theirs) != len(mine) {
		return no("the site cell differs from the cell the wallet derives")
	}
	for k := range mine {
		if !jsStrictEq(theirs[k], mine[k]) {
			return no("the site cell differs from the cell the wallet derives")
		}
	}
	return map[string]any{"ok": true, "vs": vs, "cell": mine}
}

// IntentMintDelta mints D_k from the k-th answer: ok is false when the answer added no cell ("no" answers and noise-free repeats
// produce no delta). The caller passes the PRINCIPAL key (the wallet holds it); the agent's key never signs a grant. in.Prev, when
// set, must be the id of prevGrant; Predicates are filled from the delta. cells is the number of cells the delta adds.
func IntentMintDelta(prev, next *IntentLearner, in SessionGrantInput, prevGrant map[string]any) (grant map[string]any, goalSalt string, cells int, ok bool, err error) {
	delta, err := IntentDeltaCells(prev, next)
	if err != nil {
		return nil, "", 0, false, err
	}
	for _, v := range delta {
		for _, x := range v {
			cells += int(x)
		}
	}
	if cells == 0 {
		return nil, "", 0, false, nil
	}
	id, _ := prevGrant["id"].(string)
	if in.Prev != "" && in.Prev != id {
		return nil, "", 0, false, errors.New("mintDelta: prev must be the id of the previous session grant")
	}
	in.Prev = id
	in.Predicates = IntentDeltaPredicates(next.omega, delta)
	grant, goalSalt, err = MintSessionGrant(in)
	if err != nil {
		return nil, "", 0, false, err
	}
	return grant, goalSalt, cells, true, nil
}
