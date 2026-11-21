package pca

// The confirmation flow and signed review attestations of the action importers: the attestation verdict with its reasons, review
// status, the review queue and view, and the producer side (ActionConfirmDef). A def WITHOUT a valid attestation has the top of the
// registry as its effective traits; one counts only when a key pinned with the reviewer role signed this exact def digest. Defs,
// pins and views are JSON values (map[string]any / []any).

import (
	"fmt"
	"reflect"
	"sort"
)

var (
	aivSuspect = []string{"pca.money_moving", "pca.privilege_change", "pca.code_execution", "pca.destructive", "pca.external_communication"}
	aivNext    = []string{"pca.credential_access", "pca.data_export", "pca.regulated_data", "pca.public_exposure", "pca.infra_mutation", "pca.legal_binding", "pca.impersonation", "pca.persistence"}
)

func aivFail(reason, detail string) map[string]any {
	return map[string]any{"ok": false, "reason": reason, "detail": detail}
}

// ActionVerifyAttestation is {ok: true, kid} iff the def's confirmation is valid, else {ok: false, reason, detail}: the state is
// `confirmed`; the attestation covers THIS def digest and an accepted registry digest; its final traits are the def's declared
// traits; the signer is pinned with the reviewer role inside its validity window; the signature verifies. Never panics.
func ActionVerifyAttestation(dv any, reg Registry, pins any) (res map[string]any) {
	defer func() {
		if r := recover(); r != nil {
			res = aivFail("malformed", fmt.Sprint(r))
		}
	}()
	if pe := reviewerPinsError(pins); pe != "" {
		return aivFail("bad_pins", pe)
	}
	if dv == nil {
		return aivFail("malformed", "Cannot read properties of null (reading 'review')")
	}
	d, _ := dv.(map[string]any)
	review := aisMap(d["review"])
	if review["state"] != "confirmed" {
		return aivFail("not_confirmed", "review.state is not confirmed")
	}
	av, has := review["attestation"]
	if !has {
		return aivFail("no_attestation", "a confirmed def carries an attestation")
	}
	if av == nil {
		return aivFail("malformed", "Cannot read properties of null (reading 'sig')")
	}
	a := aisMap(av) // a scalar or array has no members: unsigned
	sig, ok := a["sig"].(string)
	if !ok {
		return aivFail("no_signature", "the attestation is unsigned")
	}
	if _, ok := a["facts_digest"].(string); !ok {
		return aivFail("malformed", "the attestation facts_digest must be a string")
	}
	final, finOK := strsOf(a["final_traits"])
	dis, disOK := a["dismissed"].([]any)
	for _, x := range dis {
		m, isMap := x.(map[string]any)
		if _, t := m["trait"].(string); !isMap || !t {
			disOK = false
		} else if _, r := m["reason"].(string); !r {
			disOK = false
		}
	}
	kid, kidOK := a["reviewer_kid"].(string)
	if !finOK || !disOK || !jsIsInt(a["ts"]) || !kidOK {
		return aivFail("malformed", "the attestation final_traits, dismissed, ts or reviewer_kid is malformed")
	}
	dg, err := defDigest(d)
	if err != nil {
		return aivFail("malformed", err.Error())
	}
	if a["def_digest"] != dg {
		return aivFail("digest_mismatch", "the def changed after it was reviewed")
	}
	td, err := traitsDigest(reg)
	if err != nil {
		return aivFail("malformed", err.Error())
	}
	pm := aisMap(pins)
	if t, _ := a["traits_digest"].(string); t != td && !contains(aisStrList(pm["traits_digests"]), t) {
		return aivFail("traits_digest_mismatch", "the trait registry changed since the review")
	}
	if !reflect.DeepEqual(aisSortUniq(final), aisSortUniq(aisStrList(d["traits"]))) {
		return aivFail("final_traits_mismatch", "the attested final traits are not the def's declared traits")
	}
	for _, x := range dis {
		m := x.(map[string]any)
		if contains(final, m["trait"].(string)) || blankReason(m["reason"].(string)) {
			return aivFail("dismissed_conflict", "a dismissed trait is also final, or has no reason")
		}
	}
	var key map[string]any
	for _, kv := range aisList(pm["keys"]) {
		if k := aisMap(kv); k["kid"] == kid {
			key = k
			break
		}
	}
	if key == nil {
		return aivFail("unknown_reviewer", "no pinned key '"+kid+"'")
	}
	if !hasRole(key, "reviewer") {
		return aivFail("not_a_reviewer", "key '"+kid+"' does not hold the reviewer role")
	}
	ts := jsF(a["ts"])
	if nb, has := key["not_before"]; has && ts < jsF(nb) {
		return aivFail("outside_validity", "the attestation time is outside the key validity")
	}
	if na, has := key["not_after"]; has && ts > jsF(na) {
		return aivFail("outside_validity", "the attestation time is outside the key validity")
	}
	body := aisShallow(a)
	delete(body, "sig")
	msg, err := ActionReviewMessage(body)
	if err != nil {
		return aivFail("malformed", err.Error())
	}
	if pk, _ := key["pk"].(string); verifyB64u(pk, msg, sig) {
		return map[string]any{"ok": true, "kid": kid}
	}
	return aivFail("bad_signature", "the attestation signature is invalid")
}

// aivConfirmedVerifier is the callback the algebra takes: a confirmed def counts only if the attestation verdict is ok.
func aivConfirmedVerifier(reg Registry, pins any) ActionDiffConfirmed {
	return func(d map[string]any) bool { return ActionVerifyAttestation(d, reg, pins)["ok"] == true }
}

// ActionAttestationVerifier is the verifier to hand to the effective-traits algebra (ActionDiffConfirmed).
func ActionAttestationVerifier(reg Registry, pins any) ActionDiffConfirmed {
	return aivConfirmedVerifier(reg, pins)
}

func aivState(d map[string]any) (any, error) {
	r, ok := d["review"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Cannot read properties of undefined (reading 'state')")
	}
	return r["state"], nil
}

// ActionReviewStatus is the state that counts: a `confirmed` def with an invalid attestation is `stale` (it behaves as unreviewed).
func ActionReviewStatus(d map[string]any, reg Registry, pins any) (string, error) {
	st, err := aivState(d)
	if err != nil {
		return "", err
	}
	if st != "confirmed" {
		return jsValueString(st), nil
	}
	if ActionVerifyAttestation(d, reg, pins)["ok"] == true {
		return "confirmed", nil
	}
	return "stale", nil
}

// ActionRevertStale sends defs whose confirmation no longer holds back to `unreviewed` (the attestation is dropped); others are
// returned as they are.
func ActionRevertStale(d map[string]any, reg Registry, pins any) (map[string]any, error) {
	st, err := ActionReviewStatus(d, reg, pins)
	if err != nil {
		return nil, err
	}
	if st != "stale" {
		return d, nil
	}
	rest := aisShallow(aisMap(d["review"]))
	delete(rest, "attestation")
	rest["state"] = "unreviewed"
	out := aisShallow(d)
	out["review"] = rest
	return out, nil
}

// ---- review queue and view ---------------------------------------------------------------------------------------------------

// ActionReviewPriority is 0 = a core suspect trait (money, privilege, code, destructive, outbound communication), 1 = other risky, 2 = the rest.
func ActionReviewPriority(d map[string]any, reg Registry) (int, error) {
	e, err := adEffective(d, reg, nil)
	if err != nil {
		return 0, err
	}
	for _, t := range aivSuspect {
		if contains(e.hintCl, t) {
			return 0, nil
		}
	}
	for _, t := range aivNext {
		if contains(e.hintCl, t) {
			return 1, nil
		}
	}
	return 2, nil
}

// ActionReviewQueueOrder is the defs in review order: suspect traits first, then by risk (highest first), then by verb.
func ActionReviewQueueOrder(defs []map[string]any, reg Registry) ([]map[string]any, error) {
	type row struct {
		p, r int
		d    map[string]any
	}
	rows := make([]row, len(defs))
	for i, d := range defs {
		p, err := ActionReviewPriority(d, reg)
		if err != nil {
			return nil, err
		}
		e, err := adEffective(d, reg, nil)
		if err != nil {
			return nil, err
		}
		rows[i] = row{p, e.hintEff.Risk, d}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.p != b.p {
			return a.p < b.p
		}
		if a.r != b.r {
			return a.r > b.r
		}
		return u16Less(aisStr(a.d, "verb"), aisStr(b.d, "verb"))
	})
	out := make([]map[string]any, len(rows))
	for i, r := range rows {
		out[i] = r.d
	}
	return out, nil
}

func aivImplied(d map[string]any) ([]string, error) {
	n := normalizeDef(d)
	list, pm := normParams(n)
	ef, _ := strsOf(n["effects"])
	return impliedFromFacts(ef, list, n["resource"].(map[string]any)["scope"].(string), worstReversibility(n["reversibility"], pm))
}

// aivEffectiveView is the effective view the reviewer is shown: the all-traits view of an unconfirmed def, with the hint (what the
// def would have once signed) and the clamps the declared profile hits.
func aivEffectiveView(d map[string]any, reg Registry) (map[string]any, error) {
	decl := declProfile(d)
	hint := hintTraits(d)
	hintCl, err := reg.closure(hint)
	if err != nil {
		return nil, err
	}
	hfl, err := reg.floorOf(hint)
	if err != nil {
		return nil, err
	}
	top := topTraits(reg)
	topCl, err := reg.closure(top)
	if err != nil {
		return nil, err
	}
	tfl, err := reg.floorOf(top)
	if err != nil {
		return nil, err
	}
	clamps := []any{}
	if _, has := d["reversibility"]; has && revRank[decl.Rev] < revRank[hfl.Rev] {
		clamps = append(clamps, map[string]any{"field": "rev", "declared": decl.Rev, "floor": hfl.Rev})
	}
	if _, has := d["blast"]; has && decl.Blast < hfl.Blast {
		clamps = append(clamps, map[string]any{"field": "blast_ppm", "declared": decl.Blast, "floor": hfl.Blast})
	}
	return map[string]any{
		"confirmed": false, "traits": anyStrs(top), "closure": anyStrs(topCl), "floor": tfl.raw(), "eff": joinProfile(decl, tfl).raw(),
		"decl": decl.raw(), "clamps": clamps,
		"hint": map[string]any{"traits": anyStrs(hint), "closure": anyStrs(hintCl), "floor": hfl.raw(), "eff": joinProfile(decl, hfl).raw()},
	}, nil
}

// ActionPrepareReview is what the reviewer is shown: the def's facts, the traits it would carry once signed, the policy card and
// (with previous) the top-level members that changed (compared by value: a key-order-only difference is not a change).
func ActionPrepareReview(d map[string]any, reg Registry, previous map[string]any) (map[string]any, error) {
	rv, ok := d["review"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Cannot read properties of undefined (reading 'state')")
	}
	eff, err := aivEffectiveView(d, reg)
	if err != nil {
		return nil, err
	}
	sb := aisMap(rv["suggested_by"])
	suggested := sb["added"]
	if suggested == nil {
		suggested = map[string]any{"traits": []any{}, "roles": map[string]any{}, "tags": map[string]any{}}
	}
	changes := []string{}
	if previous != nil {
		strip := func(m map[string]any) map[string]any {
			o := aisShallow(m)
			for _, k := range []string{"review", "examples", "source", "since"} {
				delete(o, k)
			}
			return o
		}
		a, b := strip(previous), strip(d)
		keys := map[string]bool{}
		for k := range a {
			keys[k] = true
		}
		for k := range b {
			keys[k] = true
		}
		for _, k := range aisSortedKeys(keys) {
			av, aHas := a[k]
			bv, bHas := b[k]
			if aHas != bHas || !reflect.DeepEqual(normalizeJSON(av), normalizeJSON(bv)) {
				changes = append(changes, k)
			}
		}
	}
	dg, err := defDigest(d)
	if err != nil {
		return nil, err
	}
	imp, err := aivImplied(d)
	if err != nil {
		return nil, err
	}
	card, err := ActionCardOf(d, func(map[string]any) bool { return true }, reg)
	if err != nil {
		return nil, err
	}
	pri, err := ActionReviewPriority(d, reg)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"verb": d["verb"], "def_digest": dg, "state": rv["state"], "declared_traits": anyStrs(aisSortUniq(aisStrList(d["traits"]))), "implied_traits": anyStrs(imp),
		"suggested": suggested, "effective": eff, "card": card, "changes": anyStrs(changes), "priority": jsNumber(float64(pri)),
	}, nil
}

// ActionConfirmOpts is the reviewer's decision: the registry, the reviewer key (kid and Ed25519 seed), the pins the reviewer must be
// in (nil = not checked), the final DECLARED trait set, the dismissed suggestions ([{trait, reason}]) and the time.
type ActionConfirmOpts struct {
	Registry     Registry
	ReviewerKID  string
	ReviewerSeed []byte
	Pins         any
	FinalTraits  []string
	Dismissed    []any
	TS           any
}

func aivBad(code, msg string) error { return &CodedError{Code: code, Msg: msg} }

// ActionConfirmDef reviews one def: validates the decision, writes the final traits, signs an attestation over the resulting digest
// and returns the confirmed def. Errors (bad_confirm, undismissed_suggestion, not_reviewer) rather than guessing.
func ActionConfirmDef(d map[string]any, o ActionConfirmOpts) (map[string]any, error) {
	reg := o.Registry
	if !jsIsNonNeg(o.TS) {
		return nil, aivBad("bad_confirm", "ts must be a non-negative integer")
	}
	final := aisSortUniq(o.FinalTraits)
	if len(final) != len(o.FinalTraits) {
		return nil, aivBad("bad_confirm", "final traits must be distinct")
	}
	for _, t := range final {
		if _, in := reg[t]; !reTraitID.MatchString(t) || !in {
			return nil, aivBad("bad_confirm", "unknown trait '"+t+"'")
		}
		if t == "pca.unreviewed" {
			return nil, aivBad("bad_confirm", "'pca.unreviewed' is the review marker, not a final trait")
		}
	}
	type dism struct{ trait, reason string }
	dismissed := []dism{}
	dset := map[string]bool{}
	for _, x := range o.Dismissed {
		m := aisMap(x)
		tr, _ := m["trait"].(string)
		reason, isStr := m["reason"].(string)
		dismissed = append(dismissed, dism{tr, reason})
		if !isStr || jsTrim(reason) == "" || jsLen(reason) > 256 {
			return nil, aivBad("bad_confirm", "dismissed trait '"+tr+"' needs a reason (1..256 characters)")
		}
		if dset[tr] {
			return nil, aivBad("bad_confirm", "trait '"+tr+"' is dismissed twice")
		}
		dset[tr] = true
		if contains(final, tr) {
			return nil, aivBad("bad_confirm", "trait '"+tr+"' is both final and dismissed")
		}
	}
	review := aisMap(d["review"])
	added := aisMap(aisMap(review["suggested_by"])["added"])
	shown := aisSortUniq(append(aisStrList(d["traits"]), aisStrList(added["traits"])...))
	imp, err := aivImplied(d)
	if err != nil {
		return nil, err
	}
	cl, err := reg.closure(aisSortUniq(append(append([]string{}, final...), imp...)))
	if err != nil {
		return nil, err
	}
	for _, t := range shown {
		if contains(final, t) || contains(cl, t) {
			continue
		}
		if !dset[t] {
			return nil, aivBad("undismissed_suggestion", "trait '"+t+"' was suggested and is not in the final set: record it as dismissed with a reason")
		}
	}
	for _, x := range dismissed {
		if !contains(shown, x.trait) {
			return nil, aivBad("bad_confirm", "trait '"+x.trait+"' was never suggested; nothing to dismiss")
		}
	}
	if aimTruthy(o.Pins) {
		if pe := reviewerPinsError(o.Pins); pe != "" {
			return nil, aivBad("bad_confirm", pe)
		}
		var key map[string]any
		for _, kv := range aisList(aisMap(o.Pins)["keys"]) {
			if k := aisMap(kv); k["kid"] == o.ReviewerKID {
				key = k
				break
			}
		}
		if key == nil || !hasRole(key, "reviewer") {
			return nil, aivBad("not_reviewer", "key '"+o.ReviewerKID+"' is not pinned with the reviewer role")
		}
		kp, err := KeyPairFromSeed(o.ReviewerSeed)
		if err != nil {
			return nil, err
		}
		if key["pk"] != kp.Public {
			return nil, aivBad("not_reviewer", "the secret does not belong to the pinned key '"+o.ReviewerKID+"'")
		}
	}
	body := aisShallow(d)
	if len(final) == 0 {
		delete(body, "traits")
	} else {
		body["traits"] = anyStrs(final)
	}
	digest, err := defDigest(body)
	if err != nil {
		return nil, err
	}
	td, err := traitsDigest(reg)
	if err != nil {
		return nil, err
	}
	verb, _, err := ActionToSchemaVerb(body, reg, nil)
	if err != nil {
		return nil, err
	}
	fd, err := factsDigest(verb)
	if err != nil {
		return nil, err
	}
	dl := make([]any, len(dismissed))
	for i, x := range dismissed {
		dl[i] = map[string]any{"trait": x.trait, "reason": x.reason}
	}
	att, err := ActionSignReview(map[string]any{"def_digest": digest, "traits_digest": td, "facts_digest": fd, "final_traits": anyStrs(final), "dismissed": dl,
		"reviewer_kid": o.ReviewerKID, "ts": o.TS}, o.ReviewerSeed)
	if err != nil {
		return nil, err
	}
	nr := aisShallow(review)
	nr["state"] = "confirmed"
	nr["attestation"] = att
	out := aisShallow(body)
	out["review"] = nr
	if bad := validateDef(out); bad != "" {
		return nil, aivBad("bad_confirm", "the confirmed def is invalid: "+bad)
	}
	return out, nil
}
