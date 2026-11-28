package pca

// The decision functions of the intent layer with the flagship's input and output shapes: the world, provenance, class, map and
// W-B decisions, the v2 decision, accumulator values and the sequenced receipt check with its freshness bounds.

import "errors"

func withReason(out map[string]any, reason string) map[string]any {
	if reason != "" {
		out["reason"] = reason
	}
	return out
}

// DecideIntentWorld is rule 16 over {now, aud, session, action, committed?: {facts?, offer_set?}, facts?, offer_set?, policy?}: {ok: true,
// world, single_source} or {ok: false, reason}. It never panics.
func DecideIntentWorld(input any) map[string]any {
	out, reason := IntentWorldPrimitive(input)
	return withReason(out, reason)
}

// DecideParamProvenance is rule 17 over {aud, session, action, prov?, committed_labels?, labels?, policy}: {outcome: pass | question |
// deny, labels, classes, friction?, reason?}. It never panics.
func DecideParamProvenance(input any) map[string]any {
	out, reason := IntentProvenancePrimitive(input)
	return withReason(out, reason)
}

// DecideClassifierDimensions is rule 18 over {session, action, committed?, verdicts?, policy: {classifiers}}: {ok: true, classes,
// votes} or {ok: false, reason}. votes is the tally {classifier id: {label: count}} over the committed verdicts (a classifier or a
// label without a vote is absent). It never panics.
func DecideClassifierDimensions(input any) map[string]any {
	in, isMap := normalizeJSON(input).(map[string]any)
	if !isMap {
		return map[string]any{"ok": false, "reason": "classes: input must be an object"}
	}
	action, _ := in["action"].(map[string]any)
	c, cP := in["committed"]
	v, vP := in["verdicts"]
	d := decideClassifierDimensions(in["session"], action, c, cP, v, vP, in["policy"])
	if !d.ok {
		return map[string]any{"ok": false, "reason": d.reason}
	}
	votes := map[string]any{}
	for id, t := range d.votes {
		labels := map[string]any{}
		for label, n := range t {
			labels[label] = jsNumber(float64(n))
		}
		votes[id] = labels
	}
	return map[string]any{"ok": true, "classes": d.classes, "votes": votes}
}

// DecideMapDisclosure is the map check (rule 19) over {mapCommit, action: {verb, resource, params_digest}, params?, disclosure,
// maxResidualRiskPpm?}: {ok: true, cell, p_ppm} or {ok: false, reason}. It never panics.
func DecideMapDisclosure(input map[string]any) map[string]any {
	in := map[string]any{"map_commit": input["mapCommit"], "action": input["action"], "disclosure": input["disclosure"]}
	if v, has := input["params"]; has {
		in["params"] = v
	}
	if v, has := input["maxResidualRiskPpm"]; has {
		in["max_residual_risk_ppm"] = v
	}
	out, reason := IntentMapPrimitive(in)
	return withReason(out, reason)
}

// DecideIntentWB runs the W-B checks (facts, provenance, classes) over {now, aud, session, action, intent_session, artifacts?,
// policy?}: {outcome: admit | question | deny, checks, env, reason?, single_source?}. It never panics: a failure denies.
func DecideIntentWB(input map[string]any) (res map[string]any) {
	defer func() {
		if p := recover(); p != nil {
			res = map[string]any{"outcome": "deny", "checks": map[string]any{"facts": "fail"}, "env": map[string]any{}, "reason": "facts: evaluation error (fail closed)"}
		}
	}()
	action, _ := input["action"].(map[string]any)
	is, _ := input["intent_session"].(map[string]any)
	aud, _ := input["aud"].(string)
	session, _ := input["session"].(string)
	r := decideIntentWB(jsF(input["now"]), aud, session, action, is, input["artifacts"], input["policy"])
	checks := map[string]any{}
	for k, v := range r.checks {
		checks[k] = v
	}
	out := map[string]any{"outcome": r.outcome, "checks": checks, "env": r.env}
	if r.reason != "" {
		out["reason"] = r.reason
	}
	if len(r.singleSource) > 0 {
		ss := make([]any, len(r.singleSource))
		for i, s := range r.singleSource {
			ss[i] = s
		}
		out["single_source"] = ss
	}
	return out
}

// DecideIntentV2 runs the v2 checks in order for a wire-valid PCActn, the verifier's root grant, its v2 context (nil: none) and the
// clock: {checks: [{name, ok, reason?}], env, schema?, single_source?, legacy_model_polarity?}. It never panics: a failure fails the
// check being evaluated.
func DecideIntentV2(p, grant map[string]any, ctx *IntentV2Context, now float64) map[string]any {
	d := decideIntentV2(p, grant, ctx, now)
	checks := make([]any, len(d.checks))
	for i, c := range d.checks {
		m := map[string]any{"name": c.name, "ok": c.ok}
		if c.why != "" {
			m["reason"] = c.why
		}
		checks[i] = m
	}
	out := map[string]any{"checks": checks, "env": d.env}
	if d.schema != nil {
		out["schema"] = d.schema
	}
	if len(d.singleSource) > 0 {
		ss := make([]any, len(d.singleSource))
		for i, s := range d.singleSource {
			ss[i] = s
		}
		out["single_source"] = ss
	}
	if d.legacy {
		out["legacy_model_polarity"] = true
	}
	return out
}

// AccValueOf is the value an action contributes to an accumulator: {ok: true, val, key?} or {ok: false, reason}. A malformed
// declaration or schema (the reference throws) is an error.
func AccValueOf(a map[string]any, verb string, params map[string]any, schema any, haveSchema bool) (map[string]any, error) {
	v, ok, throws, reason := accValueOfReason(a, verb, params, schema, haveSchema)
	switch {
	case throws:
		return nil, errors.New("accValueOf: " + reason)
	case !ok:
		return map[string]any{"ok": false, "reason": reason}, nil
	}
	out := map[string]any{"ok": true, "val": jsNumber(v.val)}
	if v.key != "" {
		out["key"] = v.key
	}
	return out, nil
}

// CombineAcc is post_ψ: the pre-state combined with the contributed value (and, for a distinct accumulator, its key); ok is false
// when the result overflows the safe integers or the aggregate is unknown.
func CombineAcc(agg string, pre map[string]any, val float64, key string) (post float64, ok bool) {
	return combineAcc(agg, pre, accValue{val: val, key: key})
}

// ReceiptFreshness are the freshness bounds of receipt verification (policy `acc`); a nil bound takes its default.
type ReceiptFreshness struct {
	// MaxReceiptAgeMs bounds a receipt's age at verification (default 15 minutes).
	MaxReceiptAgeMs *float64
	// MaxKeySetAgeMs bounds a key set's age (default 1 hour).
	MaxKeySetAgeMs *float64
	// Tracked is the newest key set {version, digest} the verifier has accepted for the holder's root (nil: not tracked).
	Tracked map[string]any
	// MinKeySetVersion is a bare version floor for a verifier that knows versions only (nil: none).
	MinKeySetVersion *float64
}

// VerifyReceiptAgainstHolder verifies an accumulator receipt against the sequenced holder {kind: "sequenced", root, root_pq_pk?} of
// the session root: false unless the clock and every bound are safe integers, the receipt is well-formed and fresh, and some
// presented key set verifies under the holder's root (no older than the tracked or floor version, fresh, listing the receipt's key
// valid at its time under its suite) and the receipt's signature verifies under that entry.
func VerifyReceiptAgainstHolder(r map[string]any, holder map[string]any, keySets []any, now float64, f ReceiptFreshness) bool {
	fr := receiptFreshness{maxReceiptAgeMs: defaultMaxReceiptAgeMs, maxKeySetAgeMs: defaultMaxKeySetAgeMs, tracked: f.Tracked}
	if f.MaxReceiptAgeMs != nil {
		fr.maxReceiptAgeMs = *f.MaxReceiptAgeMs
	}
	if f.MaxKeySetAgeMs != nil {
		fr.maxKeySetAgeMs = *f.MaxKeySetAgeMs
	}
	sets := keySets
	if f.MinKeySetVersion != nil {
		floor := *f.MinKeySetVersion
		if !jsIsNonNeg(jsNumber(floor)) {
			return false
		}
		sets = nil
		for _, kv := range keySets {
			if k, ok := kv.(map[string]any); ok && jsIsInt(k["version"]) && jsF(k["version"]) < floor {
				continue // below the floor: the reference skips the set after it verified
			}
			sets = append(sets, kv)
		}
	}
	return verifyReceiptAgainstHolder(r, holder, sets, now, fr)
}
