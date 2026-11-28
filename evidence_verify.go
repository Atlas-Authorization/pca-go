package pca

// VerifyEvidenceBundle: the deterministic replay of a dispute evidence bundle (Intent Layer v2). Every finding is RECOMPUTED from the
// signed artifacts; nothing the bundle claims about itself (the canary summary, the accumulator posts, the verdicts) is taken on
// trust. The report text comes from fixed templates, so two readers of the same bundle with the same trust inputs get byte-identical
// reports (report_digest). Three statuses, never mixed: pass (re-verified here), fail (re-verification refuted it), unverified (this
// verifier had no way to check it); complete is false whenever one is present. It never errors on a malformed bundle: that is a
// report with a failed `shape` finding, and a fault inside the replay is a failed `shape` finding too (fail closed).

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// EvidenceAnchorLog is the name of the intent anchor log (the principal of its signed tree heads).
const EvidenceAnchorLog = "pca-intent:v1"

// EvidencePort is a verifier supplied by the reader for one artifact kind; it OVERRIDES the core default of that artifact and returns
// {ok, reason?}. trust["verifiers"][name] may be an EvidencePort or a constant {ok, reason?} verdict map.
type EvidencePort func(artifact, bundle any) map[string]any

var evTemplates = map[string]string{
	"shape":                    "The bundle is well formed (pca-intent-evidence v1, closed members)",
	"principal.pinned":         "Every session-root key that signs in this bundle is a principal key pinned by the reader (attribution)",
	"trust.principals":         "The pinned principal keys (trust.principals) are well formed",
	"statement.commit":         "The session root commits to the intent statement the bundle names",
	"statement.opening":        "The opened statement is signed by a principal and hashes to the committed ref",
	"session_root.signature":   "The session root is signed by one of its principal keys",
	"schema.signature":         "The action schema is signed by a site key",
	"schema.digest":            "The session root binds this action schema",
	"schema.anchor":            "The action schema is anchored in a transparency log",
	"map.replay":               "The task map replays to its committed digest",
	"root_grant":               "The root intent grant G_0 is principal-signed and bound to the session",
	"delta.signature":          "The delta grant is a root capability signed by a principal of the session",
	"delta.chain":              "The delta grant chains to the session (session, seq, prev, root)",
	"delta.backed":             "Every delta grant is backed by a principal \"yes\" answer",
	"answer.signature":         "The answer is signed by a principal of the session, for this session",
	"answer.map":               "The answer refers to a map version in the bundle",
	"answer.tier":              "The answer meets the site minimum friction tier for the verb",
	"answer.typed":             "The typed-tier value re-derives the signed typed digest",
	"answer.device":            "The device-tier WebAuthn assertion verifies with user verification",
	"canaries.summary":         "The canary summary equals the one recomputed from the signed canary answers",
	"pcactn.verify":            "The PCActn verifies (signature, chain, audience, validity at its issue time)",
	"pcactn.root":              "The PCActn's root capability is G_0 or a bundled delta grant",
	"pcactn.session":           "The PCActn's signed intent_session member matches the session, its root grant and the accumulator events",
	"subject.present":          "The subject PCActn is in the bundle",
	"jit.consent":              "The irreversible subject action carries a principal JIT consent bound to its exact action digest",
	"accumulator.declared":     "The accumulator is declared in the session root",
	"accumulator.arithmetic":   "The accumulator posts are the running values of the counted events",
	"accumulator.cap":          "Every accumulator post is within the admitting grant's cap",
	"accumulator.receipts":     "The sequencer reservation receipt verifies and is consistent",
	"acc.keysets.equivocation": "No two different sequencer key sets share one root and version",
	"acc.keysets":              "The sequencer key set is signed by the session's pinned sequencer root and its version never rolls back",
	"trust.acc":                "The verifier freshness configuration (trust.acc) is well formed",
	"effect.binding":           "The effect record is bound to the PCActn's signed params",
	"effect.charged":           "The charged amount is within the confirmed value",
	"effect.frame":             "No monitored state outside the write set changed",
	"effect.signature":         "The effect record is signed by the site",
	"verdict.signature":        "The site verdict record verifies",
	"fact.signature":           "The oracle fact verifies under a pinned oracle key",
	"classifier.signature":     "The classifier verdict verifies under a pinned judge key",
	"offer_set.signature":      "The offer set is signed by a site key, for this session",
	"labels.signature":         "The label receipt is signed by a pinned site key, for this session",
	"settlement.signature":     "The settlement record verifies",
	"revocation.history":       "The bundled revocation epoch extends its predecessor (one append-only chain by the session revocation authority)",
	"revocation.epoch":         "A fresh revocation epoch shows the session, its maps and its deltas unrevoked at the action time",
	"anchor.inclusion":         "The anchored artifact is included under a guardian-signed head of the intent log",
}

var evStatusText = map[string]string{"pass": "verified", "fail": "REFUTED", "unverified": "not verified here"}

var evNotProven = []string{
	"That the principal understood the question: the bundle proves only that a deterministic card with the recorded digest was shown and answered at the recorded friction tier.",
	"That the site's signed schema describes what its endpoints really do (SCH).",
	"That the site's effect records and any oracle facts are true (EFF, ORC).",
	"Acceptance of this bundle by any card network, court or regulator.",
}

var evV2Checks = []string{"schema", "intent_session", "accumulators"}

// ---- small JavaScript-flavoured helpers ----------------------------------------------------------------------------------------

func evU(v any) bool { _, ok := v.(evidUndefined); return ok }

// evSE is `a === b` where either side may be undefined.
func evSE(a, b any) bool {
	if evU(a) || evU(b) {
		return evU(a) && evU(b)
	}
	return jsStrictEq(a, b)
}

// evN is a member read where an absent member and a null are both nil (Python's dict.get).
func evN(o any, k string) any {
	v := evidGet(o, k)
	if evU(v) {
		return nil
	}
	return v
}

func evM(v any) map[string]any { m, _ := v.(map[string]any); return m }
func evL(v any) []any          { l, _ := v.([]any); return l }
func evIsObj(v any) bool       { _, ok := v.(map[string]any); return ok }

func evIsNum(v any) bool {
	f, ok := jsNum(v)
	return ok && !math.IsNaN(f) && !math.IsInf(f, 0)
}

func evF(v any) float64 { return evidToNum(v) }

// evNumOr0 is `Number(x?.[k]) || 0`.
func evNumOr0(x any, k string) float64 {
	v := evidGet(x, k)
	if evU(v) || v == nil {
		return 0
	}
	f := evidToNum(v)
	if math.IsNaN(f) {
		return 0
	}
	return f
}

func evSign(a float64) int {
	switch {
	case a < 0:
		return -1
	case a > 0:
		return 1
	}
	return 0
}

func evU16Less(a, b string) bool { return compareUnits(utf16Units(a), utf16Units(b)) < 0 }

func evSortStrings(ss []string) []string {
	out := append([]string(nil), ss...)
	sort.SliceStable(out, func(i, j int) bool { return evU16Less(out[i], out[j]) })
	return out
}

func evStrsAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func evPanicMsg(r any) string {
	switch t := r.(type) {
	case evidThrow:
		return t.msg
	case error:
		return t.Error()
	}
	return fmt.Sprint(r)
}

func evHashOK(v any) (string, bool) {
	h, err := HashCanonical(v)
	return h, err == nil
}

// evTsCheckName and evTsReason put the core verdict in the reference's words.
func evTsCheckName(n string) string {
	switch n {
	case "chain":
		return "cap_chain"
	case "freshness_anchor":
		return "freshness"
	}
	return n
}

func evTsReason(reason string) string {
	if head, rest, ok := strings.Cut(reason, ": "); ok {
		if n := evTsCheckName(head); n != head {
			reason = n + ": " + rest
		}
	}
	if reason == "leaf_signature: signature does not verify under the leaf holder key" {
		reason += " / suite"
	}
	return reason
}

func evPortOf(v any) EvidencePort {
	switch t := v.(type) {
	case EvidencePort:
		return t
	case func(artifact, bundle any) map[string]any:
		return t
	case map[string]any:
		return func(any, any) map[string]any {
			out := map[string]any{"ok": t["ok"] == true}
			if r, has := t["reason"]; has {
				out["reason"] = r
			}
			return out
		}
	}
	return nil
}

// ---- findings ------------------------------------------------------------------------------------------------------------------

type evFindings struct{ list []map[string]any }

func (f *evFindings) add(code, status string, refs []string, detail any) {
	text := evTemplates[code] + ": " + evStatusText[status]
	if detail != nil && !evU(detail) && evidTruthy(detail) {
		text += " (" + evidStr(detail) + ")"
	}
	text += "."
	f.list = append(f.list, map[string]any{"code": code, "status": status, "text": text, "refs": evStrsAny(refs)})
}

func (f *evFindings) verdict(code string, v map[string]any, refs []string) {
	if evidTruthy(v["ok"]) {
		f.add(code, "pass", refs, nil)
	} else {
		f.add(code, "fail", refs, v["reason"])
	}
}

// check runs port if supplied, else the core default; with neither the artifact stays unverified.
func (f *evFindings) check(code string, port EvidencePort, core func() map[string]any, artifact, bundle any, refs []string, what string) {
	var v map[string]any
	func() {
		defer func() {
			if r := recover(); r != nil {
				v = map[string]any{"ok": false, "reason": "verifier threw: " + evPanicMsg(r)}
			}
		}()
		if port != nil {
			v = port(artifact, bundle)
		} else if core != nil {
			v = core()
		}
	}()
	if v == nil {
		f.add(code, "unverified", refs, "no verifier for "+what)
	} else {
		f.verdict(code, v, refs)
	}
}

func evNul(e string) map[string]any {
	if e == "" {
		return map[string]any{"ok": true}
	}
	return map[string]any{"ok": false, "reason": e}
}

func evEmptySummary() map[string]any {
	np := make([]any, len(evNotProven))
	for i, s := range evNotProven {
		np[i] = s
	}
	return map[string]any{"admitted_under": nil, "principal_keys": []any{},
		"answers": map[string]any{"total": jsNumber(0), "yes": jsNumber(0), "no": jsNumber(0), "partial": jsNumber(0), "canaries": jsNumber(0)}, "refusals": []any{},
		"consent": nil, "charged": nil, "canary_accuracy": map[string]any{"correct": jsNumber(0), "asked": jsNumber(0)},
		"attribution": map[string]any{"pinned": false, "keys_to_check": []any{}}, "proven": []any{}, "not_proven": np}
}

func evFinish(f *evFindings, digest any, summary map[string]any) map[string]any {
	findings := append([]map[string]any(nil), f.list...)
	key := func(x map[string]any) [4]string {
		refs := make([]string, 0)
		for _, r := range evL(x["refs"]) {
			refs = append(refs, r.(string))
		}
		return [4]string{x["code"].(string), strings.Join(refs, ","), x["status"].(string), x["text"].(string)}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := key(findings[i]), key(findings[j])
		for k := 0; k < 4; k++ {
			if a[k] != b[k] {
				return evU16Less(a[k], b[k])
			}
		}
		return false
	})
	consistent := len(findings) > 0
	hasPinned, pinnedBad := false, false
	complete := true
	unverified := map[string]bool{}
	for _, x := range findings {
		st := x["status"].(string)
		if st == "fail" {
			consistent = false
		}
		if st == "unverified" {
			complete = false
			unverified[x["code"].(string)] = true
		}
		if x["code"] == "principal.pinned" {
			if st == "pass" {
				hasPinned = true
			} else {
				pinnedBad = true
			}
		}
	}
	attributed := hasPinned && !pinnedBad
	ok := consistent && attributed
	attr := evM(summary["attribution"])
	if keys := evL(attr["keys_to_check"]); consistent && !attributed && len(keys) > 0 {
		ks := make([]string, len(keys))
		for i, k := range keys {
			ks[i] = k.(string)
		}
		np := append([]any{"The bundle is internally consistent but NOT attributed to any known principal: verify these session-root keys out of band: " + strings.Join(ks, ", ") + "."}, evL(summary["not_proven"])...)
		summary["not_proven"] = np
	}
	if len(unverified) > 0 {
		cs := make([]string, 0, len(unverified))
		for c := range unverified {
			cs = append(cs, c)
		}
		summary["not_proven"] = append(evL(summary["not_proven"]), "Checked only through a supplied verifier, or not at all: "+strings.Join(evSortStrings(cs), ", ")+".")
	}
	fs := make([]any, len(findings))
	for i, x := range findings {
		fs[i] = x
	}
	body := map[string]any{"ok": ok, "consistent": consistent, "attributed": attributed, "complete": complete, "digest": digest, "findings": fs, "summary": summary}
	h, _ := HashCanonical(map[string]any{"d": EvidenceReportDomain, "r": body})
	body["report_digest"] = h
	return body
}

// VerifyEvidenceBundle replays a bundle against the reader's trust inputs (trust: siteKeys, principals, sessionRootDigest, minTier,
// jitTier, typedValues, credentials, canaryLabels, oracleKeys, judges, labelKeys, anchorGuardian, acc, verifiers; all optional; a
// decoded JSON object). It returns the findings report {ok, consistent, attributed, complete, digest, findings, summary, report_digest}.
func VerifyEvidenceBundle(bundle any, trust map[string]any) map[string]any {
	if trust == nil {
		trust = map[string]any{}
	}
	f := &evFindings{}
	summary := evEmptySummary()
	accV, hasAcc := trust["acc"]
	if te := EvidenceAccTrustError(accV, hasAcc); te != "" {
		f.add("trust.acc", "fail", nil, te)
		return evFinish(f, nil, summary)
	}
	prV, hasPr := trust["principals"]
	if pe := EvidencePrincipalsTrustError(prV, hasPr); pe != "" {
		f.add("trust.principals", "fail", nil, pe)
		return evFinish(f, nil, summary)
	}
	if bad := EvidenceBundleShapeError(bundle); bad != "" {
		f.add("shape", "fail", nil, bad)
		return evFinish(f, nil, summary)
	}
	nb, err := NormalizeEvidenceBundle(bundle)
	var digest string
	if err == nil {
		digest, err = EvidenceBundleDigest(nb)
	}
	if err != nil {
		f.add("shape", "fail", nil, "not canonicalizable: "+err.Error())
		return evFinish(f, nil, summary)
	}
	f.add("shape", "pass", nil, nil)
	func() {
		defer func() {
			if r := recover(); r != nil {
				f.add("shape", "fail", nil, "replay aborted: "+evPanicMsg(r))
			}
		}()
		evReplay(evM(nb), digest, trust, f, summary)
	}()
	return evFinish(f, digest, summary)
}

type evGrant struct {
	cap map[string]any
	seq int
}

type evHolder struct {
	holder map[string]any
	root   string
}

func evSeqLabel(seq int) string {
	if seq == 0 {
		return "G_0"
	}
	return fmt.Sprintf("D_%d", seq)
}

// evAccContext is the verifier context (`intentV2.acc`) for a candidate action: the pre-states of the site-local accumulators and the
// monitor states.
func evAccContext(S map[string]any, history []any, params map[string]any, t any, schema any) map[string]any {
	state := map[string]any{}
	for _, av := range evL(S["accumulators"]) {
		a := evM(av)
		if evM(a["holder"])["kind"] != "site_local" {
			continue
		}
		if a["key"] != nil {
			if _, ok := AccKeyOf(a, params); !ok {
				continue // the verifier fails the claim (missing key)
			}
		}
		if st, ok := AccPreState(a, history, params, t, schema, true); ok {
			state[a["id"].(string)] = st
		}
	}
	monitors := map[string]any{}
	for _, mv := range evL(S["monitors"]) {
		m := evM(mv)
		if s := MonitorState(m, history); s != "" {
			monitors[m["id"].(string)] = s
		} else {
			monitors[m["id"].(string)] = nil
		}
	}
	return map[string]any{"state": state, "monitors": monitors}
}

func evContains(l []string, s any) bool {
	str, ok := s.(string)
	if !ok {
		return false
	}
	for _, x := range l {
		if x == str {
			return true
		}
	}
	return false
}

func evJoin(l []any, n int) string {
	if n > len(l) {
		n = len(l)
	}
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i] = evidStr(l[i])
	}
	return strings.Join(parts, "; ")
}

func evReplay(b map[string]any, digest string, trust map[string]any, f *evFindings, summary map[string]any) {
	S := evM(b["session_root"])
	subj := evM(b["subject"])
	session, aud := subj["session"], subj["aud"]
	doc := evM(b["schema"])["doc"]
	// Consistency is checked against the keys the session root names; ATTRIBUTION (below) against the reader's pins.
	principals := []string{}
	for _, p := range evL(S["principals"]) {
		principals = append(principals, evidStr(evidGet(p, "key")))
	}
	principals = evSortStrings(principals)
	summary["principal_keys"] = evStrsAny(principals)
	var sRef any
	if v := trust["sessionRootDigest"]; v != nil {
		sRef = v
	} else {
		d, ok := SessionRootDigest(S)
		if !ok {
			evidRaise("canonicalize: unsupported value")
		}
		sRef = d
	}
	ports := evM(trust["verifiers"])
	port := func(name string) EvidencePort { return evPortOf(ports[name]) }
	// The reader's PQ pins (trust.principals[].pq_pk, out of band; NEVER the bundle's own session root principals).
	pqPins, pqPinsAny := map[string]string{}, map[string]any{}
	for _, p := range evL(trust["principals"]) {
		if pk, ok := evidGet(p, "pq_pk").(string); ok {
			k := evidStr(evidGet(p, "key"))
			pqPins[k], pqPinsAny[k] = pk, pk
		}
	}
	siteKeys := trust["siteKeys"]

	// -- session root
	if !evSE(S["session"], session) {
		f.add("session_root.signature", "fail", []string{"session_root"}, "session root is for another session")
	} else {
		f.check("session_root.signature", port("sessionRoot"), func() map[string]any { return VerifySessionRoot(S, pqPinsAny) }, S, b, []string{"session_root"}, "the session root")
	}

	// -- statement
	st := evM(b["statement"])
	if evSE(S["intent_ref"], st["commit"]) {
		f.add("statement.commit", "pass", []string{"statement"}, nil)
	} else {
		f.add("statement.commit", "fail", []string{"statement"}, nil)
	}
	opening, hasOpening := st["opening"]
	if !hasOpening {
		f.add("statement.opening", "unverified", []string{"statement"}, "the statement was not opened (it stays a commitment)")
	} else {
		ox := evM(ixIn(opening))
		if v := IntentVerifyIntent(ox, nil); v["ok"] != true {
			f.add("statement.opening", "fail", []string{"statement"}, v["reason"])
		} else if IntentRef(ox) != st["commit"] {
			f.add("statement.opening", "fail", []string{"statement"}, "the opening does not hash to the commitment")
		} else if !evContains(principals, evidGet(opening, "principal")) {
			f.add("statement.opening", "fail", []string{"statement"}, "signed by a key that is not a principal of the session")
		} else {
			f.add("statement.opening", "pass", []string{"statement"}, nil)
		}
	}

	// -- schema
	var schemaCore func() map[string]any
	if siteKeys != nil {
		schemaCore = func() map[string]any { return VerifyActionSchema(doc, siteKeys) }
	}
	f.check("schema.signature", port("schema"), schemaCore, doc, b, []string{"schema"}, "the action schema (no site keys supplied)")
	schemaDigest, ok := actionSchemaDigest(doc)
	if !ok {
		evidRaise("canonicalize: unsupported value")
	}
	sch := evM(S["schema"])
	if evSE(sch["digest"], schemaDigest) && evSE(sch["aud"], aud) {
		f.add("schema.digest", "pass", []string{"schema"}, nil)
	} else {
		f.add("schema.digest", "fail", []string{"schema"}, nil)
	}

	// -- maps
	mapCommits := []string{}
	for _, mv := range evL(b["maps"]) {
		mapCommits = append(mapCommits, evidStr(evidGet(mv, "commit")))
	}
	for _, mv := range evL(b["maps"]) {
		ref := []string{"map:" + evidStr(evidGet(mv, "seq"))}
		if !evidTruthy(evidGet(mv, "map")) {
			f.add("map.replay", "unverified", ref, "committed map not revealed")
			continue
		}
		mx := ixIn(evidGet(mv, "map"))
		if r := IntentVerifyMap(mx); r["ok"] != true {
			f.add("map.replay", "fail", ref, evJoin(evL(r["problems"]), 3))
		} else if d, err := IntentMapDigest(mx); err != nil || d != evidGet(mv, "commit") {
			f.add("map.replay", "fail", ref, "the revealed map does not hash to its commit")
		} else {
			f.add("map.replay", "pass", ref, nil)
		}
	}

	// -- grants: G_0 and the delta chain (core intent_session caveat)
	grants := map[string]*evGrant{}
	grantOrder := []string{}
	putGrant := func(id string, g *evGrant) {
		if _, has := grants[id]; !has {
			grantOrder = append(grantOrder, id)
		}
		grants[id] = g
	}
	g0 := evM(b["root_grant"])
	cv, hasCv := GrantSessionCaveat(g0)
	issuer0, _ := g0["issuer"].(string)
	why, vok := VerifyChainPolicy([]any{g0}, issuer0, true, nil, pqPins, nil)
	switch {
	case !vok:
		f.add("root_grant", "fail", []string{"G_0"}, why)
	case !evContains(principals, g0["issuer"]):
		f.add("root_grant", "fail", []string{"G_0"}, "not signed by a principal of the session")
	case !hasCv || IntentSessionCaveatError(cv) != "":
		if hasCv {
			f.add("root_grant", "fail", []string{"G_0"}, IntentSessionCaveatError(cv))
		} else {
			f.add("root_grant", "fail", []string{"G_0"}, "no intent_session caveat")
		}
	case !evSE(cv["session"], session) || !evSE(cv["seq"], jsNumber(0)) || !evSE(cv["root"], sRef):
		f.add("root_grant", "fail", []string{"G_0"}, "intent_session caveat does not bind seq 0 of this session root")
	default:
		f.add("root_grant", "pass", []string{"G_0"}, nil)
		putGrant(evidStr(g0["id"]), &evGrant{g0, 0})
	}
	prevID := g0["id"]
	deltas := evL(b["deltas"])
	for i, dv := range deltas {
		d := evM(dv)
		want := i + 1
		ref := []string{fmt.Sprintf("D_%d", want)}
		issuer, _ := d["issuer"].(string)
		why, vok := VerifyChainPolicy([]any{d}, issuer, true, nil, pqPins, nil)
		_, hasParent := d["parent"]
		if !vok || !evContains(principals, d["issuer"]) || hasParent {
			if !vok {
				f.add("delta.signature", "fail", ref, why)
			} else {
				f.add("delta.signature", "fail", ref, "not a principal-signed root capability")
			}
			continue
		}
		f.add("delta.signature", "pass", ref, nil)
		dcv, hasDcv := GrantSessionCaveat(d)
		nCv := 0
		for _, k := range evL(d["caveats"]) {
			if evidGet(k, "type") == "intent_session" {
				nCv++
			}
		}
		why2 := ""
		switch {
		case !hasDcv || nCv != 1:
			why2 = "no single intent_session caveat"
		case IntentSessionCaveatError(dcv) != "":
			why2 = IntentSessionCaveatError(dcv)
		case !evSE(dcv["session"], session):
			why2 = "bound to another session"
		case !evSE(dcv["root"], sRef):
			why2 = "bound to another session root"
		case !evSE(dcv["seq"], jsNumber(float64(want))):
			why2 = fmt.Sprintf("seq %s where %d was expected (gap, duplicate or reorder)", evidStr(dcv["seq"]), want)
		case !evSE(evidGet(dcv, "prev"), prevID):
			why2 = "prev does not name the previous grant"
		}
		if why2 != "" {
			f.add("delta.chain", "fail", ref, why2)
		} else {
			f.add("delta.chain", "pass", ref, nil)
			putGrant(evidStr(d["id"]), &evGrant{d, want})
		}
		prevID = d["id"]
	}

	// -- answers
	verified := []map[string]any{}
	for _, av := range evL(b["answers"]) {
		a := evM(av)
		qid := evidGet(a, "question_id")
		ref := []string{"answer:" + evidStr(qid)}
		v := WalletVerifyIntentAnswer(a, principals)
		if v["ok"] != true {
			f.add("answer.signature", "fail", ref, v["reason"])
			continue
		}
		if !evSE(a["session"], session) {
			f.add("answer.signature", "fail", ref, "answer for another session")
			continue
		}
		f.add("answer.signature", "pass", ref, nil)
		verified = append(verified, a)
		if evContains(mapCommits, a["map_digest"]) {
			f.add("answer.map", "pass", ref, nil)
		} else {
			f.add("answer.map", "fail", ref, nil)
		}
		ux := evM(a["ux"])
		if evidTruthy(evidGet(ux, "canary")) || !evSE(a["y"], jsNumber(1)) {
			continue
		}
		var mn any
		if mt, isObj := trust["minTier"].(map[string]any); isObj {
			if verb, isStr := a["verb"].(string); isStr {
				mn = mt[verb]
			}
		}
		if mn != nil {
			detail := evidStr(ux["tier"]) + " vs minimum " + evidStr(mn)
			if WalletFrictionRank(ux["tier"]) >= WalletFrictionRank(mn) {
				f.add("answer.tier", "pass", ref, detail)
			} else {
				f.add("answer.tier", "fail", ref, detail)
			}
		}
		if ux["tier"] == "typed" {
			var tv any
			if tvm, isObj := trust["typedValues"].(map[string]any); isObj {
				if qs, isStr := qid.(string); isStr {
					tv = tvm[qs]
				}
			}
			if tv == nil {
				f.add("answer.typed", "unverified", ref, "the typed value is not known to this verifier")
			} else {
				td, err := WalletTypedDigest(evidStr(qid), evidStr(tv))
				if err != nil {
					evidRaise(err.Error())
				}
				if evSE(td, evidGet(ux, "typed_digest")) {
					f.add("answer.typed", "pass", ref, nil)
				} else {
					f.add("answer.typed", "fail", ref, nil)
				}
			}
		}
		if ux["tier"] == "device" {
			wa := evN(ux, "webauthn")
			var cred map[string]any
			if creds, isObj := trust["credentials"].(map[string]any); isObj && evidTruthy(wa) {
				if cid, isStr := evidGet(wa, "credential_id").(string); isStr {
					cred = evM(creds[cid])
				}
			}
			if !evidTruthy(wa) || cred == nil {
				f.add("answer.device", "unverified", ref, "unknown authenticator")
				continue
			}
			dec := func(k string) []byte {
				raw, err := Unb64u(evidStr(evidRd(wa, k)))
				if err != nil {
					evidRaise(err.Error())
				}
				return raw
			}
			chal, err := WalletDeviceChallenge(evidStr(qid), evidStr(ux["rendered_digest"]), int(evF(a["y"])), evN(ux, "action_digest"))
			if err != nil {
				evidRaise(err.Error())
			}
			var origins []string
			for _, o := range evL(cred["origins"]) {
				origins = append(origins, evidStr(o))
			}
			stored := 0.0
			if sc, has := cred["signCount"]; has && sc != nil {
				stored = evF(sc)
			}
			rp, _ := cred["rpId"].(string)
			r := VerifyAssertion(Assertion{AuthenticatorData: dec("authenticator_data"), ClientDataJSON: dec("client_data_json"), Signature: dec("signature"), PublicKey: cred["publicKey"]},
				WebAuthnExpectations{ExpectedChallenge: chal, RPID: rp, Origins: origins, RequireUV: true, StoredSignCount: &stored})
			if r.OK {
				f.add("answer.device", "pass", ref, nil)
			} else {
				f.add("answer.device", "fail", ref, r.Reason)
			}
		}
	}
	real, canaries := []map[string]any{}, []map[string]any{}
	for _, a := range verified {
		if evidTruthy(evidGet(evM(a["ux"]), "canary")) {
			canaries = append(canaries, a)
		} else {
			real = append(real, a)
		}
	}
	yes, no, partial, yesCount := 0, 0, 0, 0
	refusals := []string{}
	for _, a := range real {
		_, hasPartial := a["partial"]
		if evSE(a["y"], jsNumber(1)) {
			yesCount++
			if !hasPartial {
				yes++
			}
		}
		if evSE(a["y"], jsNumber(0)) {
			no++
			refusals = append(refusals, evidStr(a["question_id"]))
		}
		if hasPartial {
			partial++
		}
	}
	n := func(i int) any { return jsNumber(float64(i)) }
	summary["answers"] = map[string]any{"total": n(len(real)), "yes": n(yes), "no": n(no), "partial": n(partial), "canaries": n(len(canaries))}
	summary["refusals"] = evStrsAny(evSortStrings(refusals))
	{
		st := "fail"
		if yesCount >= len(deltas) {
			st = "pass"
		}
		f.add("delta.backed", st, nil, fmt.Sprintf("%d delta(s), %d principal yes answer(s)", len(deltas), yesCount))
	}

	// -- canaries: recomputed, the claimed summary is never trusted
	labels := map[string]any{}
	for _, c := range evL(b["canary_labels"]) {
		labels[evidStr(evidGet(c, "question_id"))] = evidGet(c, "label")
	}
	canaryLabels, _ := trust["canaryLabels"].(map[string]any)
	falseYes, falseNo, missing := 0, 0, 0
	for _, a := range canaries {
		qs := evidStr(a["question_id"])
		label := canaryLabels[qs]
		if label == nil {
			label = labels[qs]
		}
		switch {
		case label == nil:
			missing++
		case evSE(label, jsNumber(0)) && evSE(a["y"], jsNumber(1)):
			falseYes++
		case evSE(label, jsNumber(1)) && evSE(a["y"], jsNumber(0)):
			falseNo++
		}
	}
	summary["canary_accuracy"] = map[string]any{"correct": n(len(canaries) - missing - falseYes - falseNo), "asked": n(len(canaries))}
	cs := evM(b["canaries"])
	switch {
	case missing > 0:
		f.add("canaries.summary", "fail", nil, fmt.Sprintf("%d canary answer(s) without a known label", missing))
	case !evSE(cs["asked"], n(len(canaries))) || !evSE(cs["false_yes"], n(falseYes)) || !evSE(cs["false_no"], n(falseNo)):
		f.add("canaries.summary", "fail", nil, fmt.Sprintf("claimed %s/%s/%s, recomputed %d/%d/%d", evidStr(cs["asked"]), evidStr(cs["false_yes"]), evidStr(cs["false_no"]), len(canaries), falseYes, falseNo))
	default:
		f.add("canaries.summary", "pass", nil, fmt.Sprintf("%d asked, %d false yes, %d false no", len(canaries), falseYes, falseNo))
	}

	evReplay2(b, digest, trust, f, summary, &evCtx{S: S, session: session, aud: aud, doc: doc, sRef: sRef, schemaDigest: schemaDigest, principals: principals,
		pqPins: pqPins, pqPinsAny: pqPinsAny, siteKeys: siteKeys, port: port, mapCommits: mapCommits, grants: grants, grantOrder: grantOrder, g0: g0,
		deltas: deltas, verified: verified, real: real, opening: opening, hasOpening: hasOpening})
}

type evCtx struct {
	S                 map[string]any
	session, aud, doc any
	sRef              any
	schemaDigest      string
	principals        []string
	pqPins            map[string]string
	pqPinsAny         map[string]any
	siteKeys          any
	port              func(string) EvidencePort
	mapCommits        []string
	grants            map[string]*evGrant
	grantOrder        []string
	g0                map[string]any
	deltas            []any
	verified, real    []map[string]any
	opening           any
	hasOpening        bool
}

type evKeySets struct {
	sets    []any
	minV    *float64
	tracked map[string]any
}

type evEntry struct {
	digest string
	ref    string
}

func evReplay2(b map[string]any, digest string, trust map[string]any, f *evFindings, summary map[string]any, c *evCtx) {
	S, session, aud, doc := c.S, c.session, c.aud, c.doc
	grants := c.grants
	opening := c.opening
	g0, deltas, real := c.g0, c.deltas, c.real
	n := func(i int) any { return jsNumber(float64(i)) }
	accTrust, hasAccTrust := trust["acc"].(map[string]any)
	acc := evM(b["accumulator"])

	// -- sequencer key sets (rule 15): replayed per root in issue order, versions monotone like the core keyset versions
	freshness := func(ks evKeySets) ReceiptFreshness {
		var fr ReceiptFreshness
		if hasAccTrust {
			if v := accTrust["max_receipt_age_s"]; v != nil {
				x := evF(v) * 1000
				fr.MaxReceiptAgeMs = &x
			}
			if v := accTrust["max_keyset_age_s"]; v != nil {
				x := evF(v) * 1000
				fr.MaxKeySetAgeMs = &x
			}
		}
		if ks.tracked != nil {
			fr.Tracked = ks.tracked
		} else if ks.minV != nil {
			x := *ks.minV
			fr.MinKeySetVersion = &x
		}
		return fr
	}
	rootHolders := map[string]map[string]any{}
	rootOrder := []string{}
	for _, av := range evL(S["accumulators"]) {
		h := evM(evM(av)["holder"])
		if h["kind"] == "sequenced" {
			r := evidStr(h["root"])
			if _, has := rootHolders[r]; !has {
				rootOrder = append(rootOrder, r)
			}
			rootHolders[r] = h
		}
	}
	accepted, verifiedSets := []map[string]any{}, []map[string]any{}
	equivocated := map[string]bool{}
	sets := append([]any(nil), evL(acc["sequencer_keys"])...)
	sort.SliceStable(sets, func(i, j int) bool {
		x, y := sets[i], sets[j]
		for _, k := range []string{"issued_at", "version"} {
			if d := evSign(evNumOr0(x, k) - evNumOr0(y, k)); d != 0 {
				return d < 0
			}
		}
		hx, hy := evidHash(x), evidHash(y)
		return evU16Less(hx, hy)
	})
	tracked := map[string]float64{}
	byVersion := map[string]evEntry{}
	for i, kv := range sets {
		ref := fmt.Sprintf("keyset#%d:%s", i, "?")
		k, isObj := kv.(map[string]any)
		if isObj {
			ref = fmt.Sprintf("keyset#%d:%s", i, evidStr(evidGet(k, "version")))
		}
		var holder map[string]any
		if isObj {
			if sq, isStr := k["sequencer"].(string); isStr {
				holder = rootHolders[sq]
			}
		}
		if holder == nil {
			f.add("acc.keysets", "fail", []string{ref}, "not signed by a sequencer root the session root pins")
			continue
		}
		rootPq, hasRootPq := holder["root_pq_pk"]
		if !VerifySequencerKeySet(k, holder["root"], rootPq, hasRootPq) {
			f.add("acc.keysets", "fail", []string{ref}, "the key set does not verify under its pinned root")
			continue
		}
		root := evidStr(holder["root"])
		prev, hasPrev := tracked[root]
		ver := evF(k["version"])
		if hasPrev && ver < prev {
			f.add("acc.keysets", "fail", []string{ref}, fmt.Sprintf("version %s rolls back the tracked version %s", evidStr(k["version"]), evidStr(jsNumber(prev))))
			continue
		}
		// Equivocation (core rule 15): two DIFFERENT sets under one root and version are both refused; an identical duplicate is not.
		slot := root + "#" + evidStr(k["version"])
		kd, _ := SequencerKeySetDigest(k)
		if seen, has := byVersion[slot]; has && seen.digest != kd {
			equivocated[slot] = true
			verifiedSets = append(verifiedSets, k)
			f.add("acc.keysets.equivocation", "fail", []string{seen.ref, ref}, "two different key sets under version "+evidStr(k["version"])+" of one sequencer root")
			continue
		} else if !has {
			byVersion[slot] = evEntry{kd, ref}
		}
		verifiedSets = append(verifiedSets, k)
		tracked[root] = math.Max(prev, ver)
		accepted = append(accepted, k)
		f.add("acc.keysets", "pass", []string{ref}, nil)
	}
	{
		kept := accepted[:0:0]
		for _, k := range accepted {
			if !equivocated[evidStr(k["sequencer"])+"#"+evidStr(k["version"])] {
				kept = append(kept, k)
			}
		}
		accepted = kept
	}
	// keySetsAt: in force = the accepted sets of the root issued by admission (+ the core skew); the tracked state is the newest
	// VERIFIED set issued by then.
	keySetsAt := func(root string, t any) evKeySets {
		var newest map[string]any
		for _, k := range verifiedSets {
			if k["sequencer"] == root && evF(k["issued_at"]) <= evF(t) && (newest == nil || evF(k["version"]) > evF(newest["version"])) {
				newest = k
			}
		}
		poisoned := newest != nil && equivocated[root+"#"+evidStr(newest["version"])]
		floor := 0.0
		if newest != nil {
			floor = evF(newest["version"])
		}
		out := evKeySets{sets: []any{}}
		for _, k := range accepted {
			if k["sequencer"] == root && evF(k["issued_at"]) <= evF(t)+ReceiptSkewMs && evF(k["version"]) >= floor {
				out.sets = append(out.sets, k)
			}
		}
		if newest != nil {
			v := evF(newest["version"])
			out.minV = &v
			if !poisoned {
				kd, _ := SequencerKeySetDigest(newest)
				out.tracked = map[string]any{"version": newest["version"], "digest": kd}
			}
		}
		return out
	}

	// -- PCActns
	byDigest := map[string]map[string]any{}
	digestOrder := []string{}
	rootSeq := map[string]int{}
	effects := evL(b["effects"])
	effectOf := func(d string) any {
		for _, e := range effects {
			if evidGet(e, "pcactn_digest") == any(d) {
				return e
			}
		}
		return nil
	}
	digestOf := func(p any) (string, bool) { return evHashOK(p) }
	byseq := make([]*evGrant, 0, len(grants))
	for _, id := range c.grantOrder {
		byseq = append(byseq, grants[id])
	}
	sort.SliceStable(byseq, func(i, j int) bool { return byseq[i].seq < byseq[j].seq })
	grantsBySeq := make([]any, len(byseq))
	for i, g := range byseq {
		grantsBySeq[i] = g.cap
	}
	epochs := evL(b["revocation_epochs"])
	epochIdxAt := func(t any) int {
		idx := -1
		for i, r := range epochs {
			if evF(evidGet(evidGet(r, "epoch"), "issued_at")) <= evF(t) {
				idx = i
			}
		}
		return idx
	}
	// The admitted history, as the site's store held it: one event per accumulator-bearing PCActn, in event order.
	history := []any{}
	events := evL(acc["events"])
	for _, ev := range events {
		pd := evidGet(ev, "pcactn_digest")
		seen := false
		for _, h := range history {
			if evSE(evM(h)["id"], pd) {
				seen = true
			}
		}
		if seen {
			continue
		}
		var p map[string]any
		for _, x := range evL(b["pcactns"]) {
			if d, ok := digestOf(x); ok && any(d) == pd {
				p = evM(x)
				break
			}
		}
		eff := effectOf(evidStr(pd))
		var params any
		if em, ok := eff.(map[string]any); ok {
			params = em["params"]
		}
		if p != nil && evidTruthy(params) {
			status := evN(ev, "status")
			if status == nil {
				status = "committed"
			}
			history = append(history, map[string]any{"id": pd, "verb": evidRd(evidRd(p, "action"), "verb"), "resource": evidRd(evidRd(p, "action"), "resource"),
				"params": params, "t": evidRd(p, "iat"), "status": status})
		}
	}
	siteKeys := c.siteKeys
	v2Context := func(p map[string]any, d string, seq int, hasSeq bool) map[string]any {
		var params any
		if em, ok := effectOf(d).(map[string]any); ok {
			params = em["params"]
		}
		if !evidTruthy(params) || !hasSeq {
			return nil
		}
		idx := -1
		for i, h := range history {
			if evSE(evM(h)["id"], d) {
				idx = i
				break
			}
		}
		var before []any
		if idx >= 0 {
			before = history[:idx]
		} else {
			for _, h := range history {
				if evF(evM(h)["t"]) <= evF(p["iat"]) {
					before = append(before, h)
				}
			}
		}
		pm, _ := params.(map[string]any)
		accCtx := evAccContext(S, before, pm, p["iat"], map[string]any{"verbs": evM(doc)["verbs"]})
		ri := epochIdxAt(p["iat"])
		kv := map[string]any{}
		seqKeys := []any{}
		for _, root := range rootOrder {
			ks := keySetsAt(root, p["iat"])
			if ks.tracked != nil {
				kv[root] = ks.tracked
			}
			seqKeys = append(seqKeys, ks.sets...)
		}
		gs := grantsBySeq
		if seq < len(gs) {
			gs = gs[:seq]
		}
		sessionCtx := map[string]any{"root": S, "grants": gs, "pq_pins": c.pqPinsAny}
		if ri >= 0 {
			sessionCtx["revocation"] = epochs[ri]
		}
		if ri > 0 {
			sessionCtx["revocation_last"] = epochs[ri-1]
		}
		receipts := evN(acc, "receipts")
		if receipts == nil {
			receipts = []any{}
		}
		accCtx["receipts"], accCtx["sequencer_keys"], accCtx["keyset_versions"] = receipts, seqKeys, kv
		keys := siteKeys
		if keys == nil {
			keys = []any{}
		}
		ctx := map[string]any{"params": params, "schema": map[string]any{"docs": []any{doc}, "keys": keys}, "session": sessionCtx, "acc": accCtx}
		if hasAccTrust {
			ctx["policy"] = map[string]any{"acc": accTrust}
		}
		return ctx
	}
	for _, pv := range evL(b["pcactns"]) {
		p, _ := pv.(map[string]any)
		d, dok := digestOf(pv)
		if !dok {
			f.add("pcactn.verify", "fail", []string{"pcactn:?"}, "not canonicalizable")
			continue
		}
		if _, has := byDigest[d]; !has {
			digestOrder = append(digestOrder, d)
		}
		byDigest[d] = p
		ref := []string{"pcactn:" + d}
		chain, _ := p["cap_chain"].([]any)
		var root any
		if len(chain) > 0 {
			root = chain[0]
		}
		if !evidTruthy(root) {
			f.add("pcactn.verify", "fail", ref, "empty capability chain")
			continue
		}
		var g *evGrant
		if rid, isStr := evidGet(root, "id").(string); isStr {
			g = grants[rid]
		}
		sameRoot := false
		if g != nil {
			gh, ok1 := evHashOK(g.cap)
			rh, ok2 := evHashOK(root)
			sameRoot = ok1 && ok2 && gh == rh
		}
		is := evidGet(p, "intent_session")
		var ctx map[string]any
		if !evU(is) && sameRoot {
			ctx = v2Context(p, d, g.seq, true)
		}
		// The root's authority is pcactn.root (byte-equal to G_0 / a verified delta) plus principal.pinned (trust.principals): a
		// non-Ed25519 root verifies only under the reader's pins, else it is refused.
		opts := VerifyOptions{InsecureSkipPlanRootCheck: true, PQPins: c.pqPins}
		if ctx != nil {
			opts.IntentV2 = IntentV2ContextFromJSON(ctx)
		}
		rm, _ := root.(map[string]any)
		vd, err := VerifyPCActnCoreWith(p, rm, int64(evF(evidRd(p, "iat"))), evidStr(aud), opts)
		if err != nil {
			evidRaise(err.Error())
		}
		failed := []string{}
		for k, ok := range vd.Checks {
			if !ok {
				failed = append(failed, evTsCheckName(k))
			}
		}
		failed = evSortStrings(failed)
		v1f, v2f := []string{}, []string{}
		for _, k := range failed {
			if k == evV2Checks[0] || k == evV2Checks[1] || k == evV2Checks[2] {
				v2f = append(v2f, k)
			} else {
				v1f = append(v1f, k)
			}
		}
		if len(v1f) > 0 {
			f.add("pcactn.verify", "fail", ref, strings.Join(v1f, ", ")+": "+evTsReason(vd.Reason))
		} else {
			f.add("pcactn.verify", "pass", ref, nil)
		}
		if sameRoot {
			f.add("pcactn.root", "pass", ref, evSeqLabel(g.seq))
			rootSeq[d] = g.seq
		} else {
			f.add("pcactn.root", "fail", ref, "rooted at a grant that is not G_0 or a verified delta of this session")
		}
		if !evU(is) {
			why := ""
			switch {
			case !evSE(evidGet(is, "session"), session):
				why = "another session"
			case !evSE(evidGet(is, "root"), c.sRef):
				why = "another session root"
			case !evSE(evidGet(is, "schema"), c.schemaDigest):
				why = "another schema"
			case g != nil && !evSE(evidGet(is, "seq"), jsNumber(float64(g.seq))):
				why = fmt.Sprintf("seq %s but rooted at seq %d", evidStr(evidGet(is, "seq")), g.seq)
			default:
				claims := evidGet(is, "acc")
				if evU(claims) || claims == nil {
					claims = []any{}
				}
				cl, isList := claims.([]any)
				if !isList {
					evidRaise("is_.acc is not iterable")
				}
				for _, x := range cl {
					var ev any
					for _, e := range events {
						if evidGet(e, "pcactn_digest") == any(d) && evSE(evidGet(e, "acc"), evidGet(x, "id")) {
							ev = e
							break
						}
					}
					if ev == nil || !evSE(evidGet(ev, "post"), evidGet(x, "post")) {
						why = fmt.Sprintf("the signed claim %s.post = %s has no matching accumulator event", evidStr(evidGet(x, "id")), evidStr(evidGet(x, "post")))
					}
				}
			}
			if why == "" && len(v2f) > 0 {
				why = "core v2 checks failed: " + strings.Join(v2f, ", ")
			}
			switch {
			case why != "":
				f.add("pcactn.session", "fail", ref, why)
			case ctx == nil:
				f.add("pcactn.session", "unverified", ref, "the core v2 checks need the plaintext params of the effect record")
			default:
				f.add("pcactn.session", "pass", ref, nil)
			}
		}
	}
	subjDigest := evidStr(evM(b["subject"])["pcactn_digest"])
	subject, hasSubject := byDigest[subjDigest]
	if hasSubject {
		f.add("subject.present", "pass", []string{"pcactn:" + subjDigest}, nil)
	} else {
		f.add("subject.present", "fail", []string{"pcactn:" + subjDigest}, nil)
	}
	if sSeq, has := rootSeq[subjDigest]; has {
		summary["admitted_under"] = evSeqLabel(sSeq)
	} else {
		summary["admitted_under"] = nil
	}

	evReplay3(b, digest, trust, f, summary, c, &evCtx2{n: n, accepted: accepted, rootHolders: rootHolders, rootOrder: rootOrder, keySetsAt: keySetsAt, freshness: freshness, byDigest: byDigest,
		digestOrder: digestOrder, rootSeq: rootSeq, effectOf: effectOf, epochs: epochs, epochIdxAt: epochIdxAt, subject: subject, hasSubject: hasSubject, subjDigest: subjDigest})
	_, _, _, _ = g0, deltas, real, opening
}

type evCtx2 struct {
	n           func(int) any
	accepted    []map[string]any
	rootHolders map[string]map[string]any
	rootOrder   []string
	keySetsAt   func(string, any) evKeySets
	freshness   func(evKeySets) ReceiptFreshness
	byDigest    map[string]map[string]any
	digestOrder []string
	rootSeq     map[string]int
	effectOf    func(string) any
	epochs      []any
	epochIdxAt  func(any) int
	subject     map[string]any
	hasSubject  bool
	subjDigest  string
}

func evEqN(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return jsStrictEq(a, b)
}

func evReplay3(b map[string]any, digest string, trust map[string]any, f *evFindings, summary map[string]any, c *evCtx, c2 *evCtx2) {
	S, session, aud, doc := c.S, c.session, c.aud, c.doc
	grants, port := c.grants, c.port
	g0, deltas, real, opening := c.g0, c.deltas, c.real, c.opening
	n := c2.n
	byDigest, effects := c2.byDigest, evL(b["effects"])
	effectOf := c2.effectOf
	acc := evM(b["accumulator"])
	subject, hasSubject, subjDigest := c2.subject, c2.hasSubject, c2.subjDigest
	siteKeys := c.siteKeys
	events := evL(acc["events"])

	// -- effects (no core format yet: signature through the port)
	for _, ev := range effects {
		e := evM(ev)
		ref := []string{"effect:" + evidStr(e["pcactn_digest"])}
		pd, _ := e["pcactn_digest"].(string)
		p, has := byDigest[pd]
		if !has {
			f.add("effect.binding", "fail", ref, "no such PCActn in the bundle")
			continue
		}
		if _, hasParams := e["params"]; !hasParams {
			f.add("effect.binding", "unverified", ref, "no raw params to bind")
		} else {
			d, err := ParamsDigest(e["params"])
			if err != nil {
				evidRaise(err.Error())
			}
			if evSE(d, evidRd(evidRd(p, "action"), "params_digest")) {
				f.add("effect.binding", "pass", ref, nil)
			} else {
				f.add("effect.binding", "fail", ref, nil)
			}
		}
		if charged := evidGet(e, "charged"); evidTruthy(charged) {
			cref := evidGet(charged, "ref")
			name := ""
			hasName := false
			if cs, isStr := cref.(string); isStr && strings.HasPrefix(cs, "action.params.") {
				name, hasName = cs[len("action.params."):], true
			}
			var bound any = evidUndef
			if pm, isObj := e["params"].(map[string]any); isObj && hasName && evidTruthy(pm) {
				if v, ok := pm[name]; ok {
					bound = v
				}
			}
			amount := evidGet(charged, "amount")
			if !evIsNum(bound) || !evIsNum(amount) {
				f.add("effect.charged", "unverified", ref, "no numeric "+evidStr(cref)+" to compare")
			} else {
				detail := evidStr(amount) + " vs " + evidStr(bound)
				if evF(amount) <= evF(bound) {
					f.add("effect.charged", "pass", ref, detail)
				} else {
					f.add("effect.charged", "fail", ref, detail)
				}
				if pd == subjDigest {
					summary["charged"] = map[string]any{"amount": amount, "bound": bound}
				}
			}
		}
		if fv, has := e["frame_violations"]; has {
			l := evL(fv)
			if len(l) == 0 {
				f.add("effect.frame", "pass", ref, nil)
			} else {
				ss := make([]string, len(l))
				for i, x := range l {
					ss[i] = evidStr(x)
				}
				f.add("effect.frame", "fail", ref, strings.Join(evSortStrings(ss), ", "))
			}
		}
		f.check("effect.signature", port("effect"), nil, e, b, ref, "effect records (no core format yet)")
	}

	// -- JIT consent for an irreversible subject action (core action digest)
	if hasSubject && evidGet(evidRd(subject, "action"), "reversibility_class") == "irreversible" {
		ref := []string{"pcactn:" + subjDigest}
		ad := IntentActionDigest(evM(ixIn(subject["action"])))
		var need any = "typed"
		if v := trust["jitTier"]; v != nil {
			need = v
		}
		var cons map[string]any
		for _, a := range real {
			ux := evM(a["ux"])
			if evSE(a["y"], jsNumber(1)) && ux["consent_for_action"] == true && evSE(evidGet(ux, "action_digest"), ad) && WalletFrictionRank(ux["tier"]) >= WalletFrictionRank(need) {
				cons = a
				break
			}
		}
		if cons != nil {
			ux := evM(cons["ux"])
			f.add("jit.consent", "pass", ref, "question "+evidStr(cons["question_id"])+", "+evidStr(ux["tier"])+" tier")
			summary["consent"] = map[string]any{"question_id": cons["question_id"], "tier": ux["tier"], "signer": cons["signer"]}
		} else {
			f.add("jit.consent", "fail", ref, "no principal yes at "+evidStr(need)+" tier or above bound to this action digest")
		}
	}

	// -- accumulators (core declarations and value rule)
	decls := map[string]map[string]any{}
	for _, av := range evL(S["accumulators"]) {
		decls[evidStr(evM(av)["id"])] = evM(av)
	}
	schemaVerbs := map[string]any{"verbs": evM(doc)["verbs"]}
	valueOf := func(decl map[string]any, d string) any {
		p, has := byDigest[d]
		var params any
		if em, ok := effectOf(d).(map[string]any); ok {
			params = em["params"]
		}
		if !has || !evidTruthy(params) {
			return nil
		}
		pm, _ := params.(map[string]any)
		v, err := AccValueOf(decl, evidStr(evidRd(evidRd(p, "action"), "verb")), pm, schemaVerbs, true)
		if err != nil {
			evidRaise(err.Error())
		}
		if v["ok"] == true {
			return v["val"]
		}
		return nil
	}
	running := map[string]float64{}
	for i, ev := range events {
		accID := evidStr(evidGet(ev, "acc"))
		ref := []string{fmt.Sprintf("acc:%s#%d", accID, i)}
		decl := decls[accID]
		if decl == nil {
			f.add("accumulator.declared", "fail", ref, nil)
			continue
		}
		evd := evidStr(evidGet(ev, "pcactn_digest"))
		p, hasP := byDigest[evd]
		status := evidGet(ev, "status")
		counted := status != "released" && status != "reverted"
		prev := running[accID]
		var expected *float64
		post := evF(evidGet(ev, "post"))
		agg := decl["agg"]
		switch {
		case !counted:
			x := prev
			expected = &x
		case agg == "count":
			x := prev + 1
			expected = &x
		case agg == "sum" || agg == "max":
			if val := valueOf(decl, evd); val != nil {
				var x float64
				if agg == "sum" {
					x = prev + evF(val)
				} else {
					x = math.Max(prev, evF(val))
				}
				expected = &x
			}
		}
		switch {
		case !hasP:
			f.add("accumulator.arithmetic", "fail", ref, "event names a PCActn that is not in the bundle")
		case expected == nil:
			if post >= prev {
				f.add("accumulator.arithmetic", "unverified", ref, "contribution not recomputable")
			} else {
				f.add("accumulator.arithmetic", "fail", ref, "post decreased")
			}
		case post == *expected:
			f.add("accumulator.arithmetic", "pass", ref, nil)
		default:
			f.add("accumulator.arithmetic", "fail", ref, "post "+evidStr(evidGet(ev, "post"))+", recomputed "+evidStr(jsNumber(*expected)))
		}
		if counted {
			running[accID] = post
		} else {
			running[accID] = prev
		}
		if !counted {
			continue
		}
		seq, hasSeq := 0, false
		if hasP {
			seq, hasSeq = c2.rootSeq[evd]
		}
		delta := evidGet(ev, "delta")
		if !evU(delta) && hasSeq && !evSE(delta, jsNumber(float64(seq))) {
			f.add("accumulator.cap", "fail", ref, "the event names a different admitting grant from the PCActn root")
			continue
		}
		var wantSeq any = delta
		if hasSeq {
			wantSeq = jsNumber(float64(seq))
		}
		var grant *evGrant
		for _, id := range c.grantOrder {
			if g := grants[id]; evSE(jsNumber(float64(g.seq)), wantSeq) {
				grant = g
				break
			}
		}
		caps := []float64{}
		if grant != nil && hasP {
			cv, err := EvidenceCapOf(grant.cap, accID, evidStr(evidRd(evidRd(p, "action"), "verb")))
			if err != nil {
				evidRaise(err.Error())
			}
			if cv != nil {
				caps = append(caps, evF(cv))
			}
		}
		if dm := decl["domain_max"]; evIsNum(dm) {
			caps = append(caps, evF(dm))
		}
		if cp := decl["cap"]; evIsNum(cp) {
			caps = append(caps, evF(cp))
		}
		if len(caps) == 0 {
			f.add("accumulator.cap", "unverified", ref, "no cap stated for this accumulator")
		} else {
			capv := caps[0]
			for _, x := range caps[1:] {
				capv = math.Min(capv, x)
			}
			detail := "post " + evidStr(evidGet(ev, "post")) + ", cap " + evidStr(jsNumber(capv))
			if evIsNum(evidGet(ev, "post")) && post <= capv {
				f.add("accumulator.cap", "pass", ref, detail)
			} else {
				f.add("accumulator.cap", "fail", ref, detail)
			}
		}
	}
	receipts := evL(evN(acc, "receipts"))
	if acc["holder"] == "sequenced" && len(receipts) == 0 {
		f.add("accumulator.receipts", "fail", []string{"accumulator"}, "a sequenced accumulator without receipts")
	}
	for i, rv := range receipts {
		r := evM(rv)
		core := func() map[string]any {
			// nil = the signature and freshness held but the contribution cannot be recomputed (params withheld): unverified.
			decl := decls[evidStr(evidGet(r, "acc"))]
			if decl == nil || evM(decl["holder"])["kind"] != "sequenced" {
				return map[string]any{"ok": false, "reason": "the receipt names an accumulator that is not sequenced in the session root"}
			}
			holder := evM(decl["holder"])
			if !evSE(r["session"], session) || !evSE(r["aud"], aud) {
				return map[string]any{"ok": false, "reason": "receipt for another session or audience"}
			}
			d, found := "", false
			for _, dd := range c2.digestOrder {
				if rd, ok := PcactnReservationDigest(c2.byDigest[dd]); ok && evSE(rd, r["pcactn_digest"]) {
					d, found = dd, true
					break
				}
			}
			if !found {
				return map[string]any{"ok": false, "reason": "the receipt reserves for a PCActn that is not in the bundle"}
			}
			// Rule 15 freshness is judged at ADMISSION time (the reserved PCActn's iat), never at bundle-verification time.
			admittedAt := evidRd(byDigest[d], "iat")
			ks := c2.keySetsAt(evidStr(holder["root"]), admittedAt)
			if !VerifyReceiptAgainstHolder(r, holder, ks.sets, evF(admittedAt), c2.freshness(ks)) {
				return map[string]any{"ok": false, "reason": "not signed by a key the pinned sequencer root listed, or not fresh, at admission time"}
			}
			if !(evIsNum(admittedAt) && evIsNum(r["expires_at"]) && evF(admittedAt) <= evF(r["expires_at"])) {
				return map[string]any{"ok": false, "reason": "the receipt had expired when the action was admitted"}
			}
			val := valueOf(decl, d)
			if val == nil {
				return nil
			}
			if !ReceiptArithmeticOk(evidStr(decl["agg"]), r, evF(val)) {
				return map[string]any{"ok": false, "reason": "pre + delta does not give post for the reserved value"}
			}
			return map[string]any{"ok": true}
		}
		rs := evidGet(r, "seq")
		label := i
		var lbl string
		if evU(rs) || rs == nil {
			lbl = fmt.Sprint(label)
		} else {
			lbl = evidStr(rs)
		}
		f.check("accumulator.receipts", port("receipt"), core, r, b, []string{"receipt:" + evidStr(evidGet(r, "acc")) + "#" + lbl}, "the reserved contribution (the effect params were withheld)")
	}

	// -- W-B artifacts: facts, classifier verdicts, offer sets, label receipts
	oracleKeys, _ := trust["oracleKeys"].(map[string]any)
	for i, xv := range evL(evN(b, "facts")) {
		var pk any
		if x, isObj := xv.(map[string]any); isObj {
			if on, isStr := x["oracle"].(string); isStr && oracleKeys != nil {
				pk = oracleKeys[on]
			}
		}
		fx := xv
		fpk := pk
		var core func() map[string]any
		if pk != nil {
			core = func() map[string]any {
				if w := ValidateFactWire(fx); w != "" {
					return map[string]any{"ok": false, "reason": w}
				}
				if VerifyArtifactSig(FactDomain, evM(fx), fpk, nil) {
					return map[string]any{"ok": true}
				}
				return map[string]any{"ok": false, "reason": "bad oracle signature"}
			}
		}
		f.check("fact.signature", port("fact"), core, xv, b, []string{fmt.Sprintf("fact:%d", i)}, "this fact (oracle key not pinned)")
	}
	judges := []string{}
	for _, j := range evL(trust["judges"]) {
		if s, ok := j.(string); ok {
			judges = append(judges, s)
		}
	}
	for i, xv := range evL(evN(b, "classifier")) {
		var judge any
		if x, isObj := xv.(map[string]any); isObj {
			if js, isStr := x["judge"].(string); isStr {
				judge = js
			}
		}
		cx := xv
		cj := judge
		var core func() map[string]any
		if judge != nil && evContains(judges, judge) {
			core = func() map[string]any {
				if w := ValidateClassifierVerdictWire(cx); w != "" {
					return map[string]any{"ok": false, "reason": w}
				}
				if !evSE(evidGet(cx, "session"), session) {
					return map[string]any{"ok": false, "reason": "verdict for another session"}
				}
				if VerifyArtifactSig(IntentClassifierDomain, evM(cx), cj, nil) {
					return map[string]any{"ok": true}
				}
				return map[string]any{"ok": false, "reason": "bad judge signature"}
			}
		}
		f.check("classifier.signature", port("classifier"), core, xv, b, []string{fmt.Sprintf("classifier:%d", i)}, "this classifier verdict (judge not pinned)")
	}
	for i, xv := range evL(evN(b, "offer_sets")) {
		var key map[string]any
		if x, isObj := xv.(map[string]any); isObj {
			for _, kv := range evL(siteKeys) {
				if evSE(evidGet(kv, "kid"), evidGet(x, "kid")) && evidGet(kv, "alg") == "ed25519" {
					key = evM(kv)
					break
				}
			}
		}
		ox := xv
		okey := key
		var core func() map[string]any
		if key != nil {
			core = func() map[string]any {
				if w := ValidateOfferSetWire(ox); w != "" {
					return map[string]any{"ok": false, "reason": w}
				}
				if !evSE(evidGet(ox, "session"), session) {
					return map[string]any{"ok": false, "reason": "offer set for another session"}
				}
				if VerifyArtifactSig(OfferSetDomain, evM(ox), okey["pk"], nil) {
					return map[string]any{"ok": true}
				}
				return map[string]any{"ok": false, "reason": "bad site signature"}
			}
		}
		f.check("offer_set.signature", port("offerSet"), core, xv, b, []string{fmt.Sprintf("offer_set:%d", i)}, "this offer set (site key not pinned)")
	}
	var labelKeys []any
	if lk, has := trust["labelKeys"]; has && lk != nil {
		labelKeys = evL(lk)
	} else {
		for _, kv := range evL(siteKeys) {
			if evidGet(kv, "alg") == "ed25519" {
				labelKeys = append(labelKeys, map[string]any{"site": evM(doc)["site"], "kid": evidRd(kv, "kid"), "pk": evidRd(kv, "pk")})
			}
		}
	}
	for i, xv := range evL(evN(b, "labels")) {
		lx := xv
		var core func() map[string]any
		if len(labelKeys) > 0 {
			core = func() map[string]any {
				e := VerifyLabels(lx, labelKeys)
				if e == "" && !evSE(evidGet(lx, "session"), session) {
					return map[string]any{"ok": false, "reason": "label receipt for another session"}
				}
				return evNul(e)
			}
		}
		f.check("labels.signature", port("labels"), core, xv, b, []string{fmt.Sprintf("labels:%d", i)}, "this label receipt (no site keys)")
	}

	// -- ported artifacts with no core format
	for _, v := range evL(b["verdicts"]) {
		f.check("verdict.signature", port("verdict"), nil, v, b, []string{"verdict:" + evidStr(evidGet(v, "pcactn_digest"))}, "site verdicts (no core format yet)")
	}
	for i, x := range evL(evN(b, "settlements")) {
		f.check("settlement.signature", port("settlement"), nil, x, b, []string{fmt.Sprintf("settlement:%d", i)}, "settlement records (no core format yet)")
	}

	evReplay4(b, digest, trust, f, summary, c, c2, n, g0, deltas, opening)
}

func evReplay4(b map[string]any, digest string, trust map[string]any, f *evFindings, summary map[string]any, c *evCtx, c2 *evCtx2, n func(int) any, g0 map[string]any, deltas []any, opening any) {
	S, session := c.S, c.session
	subject, hasSubject := c2.subject, c2.hasSubject
	epochs := c2.epochs

	// -- revocation (core check_session_revocation, rule 13 step 7)
	// The bundle's epochs, in issue order, must form ONE append-only chain signed by the session's dedicated revocation authority:
	// every epoch is checked as of its own issue time with its predecessor as the tracked `last`; the epoch in force at the action
	// time decides.
	rev := evidGet(S, "revocation")
	switch {
	case len(epochs) == 0:
		f.add("revocation.epoch", "unverified", nil, "no revocation epoch in the bundle")
	case !evidTruthy(rev):
		f.add("revocation.epoch", "fail", nil, "the session root names no revocation authority")
	default:
		authority := evidRd(rev, "key")
		var maxAgeMs any = jsNumber(float64(DefaultRevocationMaxAgeS["default"]) * 1000)
		if ma := evN(rev, "max_age_s"); ma != nil {
			maxAgeMs = jsNumber(evF(ma) * 1000)
		}
		var pin map[string]string
		if pq := evidGet(rev, "pq_pk"); !evU(pq) {
			pin = map[string]string{evidStr(authority): evidStr(pq)}
		}
		rcheck := func(ev any, ids []any, now any, last any, hasLast bool) map[string]any {
			return CheckSessionRevocation(ev, session, authority, ids, now, maxAgeMs, last, hasLast, pin)
		}
		historyOK := true
		for i, ev := range epochs {
			var last any
			if i > 0 {
				last = epochs[i-1]
			}
			v := rcheck(ev, []any{}, evidGet(evidGet(ev, "epoch"), "issued_at"), last, i > 0)
			if v["ok"] != true {
				historyOK = false
			}
			f.verdict("revocation.history", v, []string{fmt.Sprintf("epoch#%d:%s", i, evidStr(evidGet(evidGet(ev, "epoch"), "epoch")))})
		}
		if !hasSubject {
			f.add("revocation.epoch", "unverified", nil, "no subject action time")
		} else {
			ids := []any{SessionRevocationId(evidStr(session))}
			for _, mv := range evL(b["maps"]) {
				ids = append(ids, MapRevocationId(evidStr(evidGet(mv, "commit"))))
			}
			for _, d := range deltas {
				ids = append(ids, DeltaRevocationId(evidStr(evidGet(d, "id"))))
			}
			idx := c2.epochIdxAt(subject["iat"])
			if idx < 0 {
				f.add("revocation.epoch", "fail", nil, "every epoch was issued after the action")
			} else {
				ev := epochs[idx]
				ref := []string{"epoch:" + evidStr(evidGet(evidGet(ev, "epoch"), "epoch"))}
				if !historyOK {
					f.add("revocation.epoch", "fail", ref, "the bundled epochs are not one append-only chain")
				} else {
					var last any
					if idx > 0 {
						last = epochs[idx-1]
					}
					f.verdict("revocation.epoch", rcheck(ev, ids, subject["iat"], last, idx > 0), ref)
				}
			}
		}
	}

	// -- anchors
	if evidTruthy(evidGet(evM(b["schema"]), "anchor")) {
		f.add("schema.anchor", "unverified", []string{"schema"}, "the anchor names a log position without an inclusion proof")
	}
	anchors := evL(b["anchors"])
	st := evM(b["statement"])
	anchorable := func(kind, d any) bool {
		switch kind {
		case "evidence":
			return evSE(d, digest)
		case "statement":
			return evSE(d, st["commit"])
		case "map":
			return evContains(c.mapCommits, d)
		case "schema":
			return evSE(d, c.schemaDigest)
		case "observation":
			for _, a := range c.verified {
				if r, err := WalletAnswerRef(a); err == nil && evSE(r, d) {
					return true
				}
			}
		}
		return false
	}
	hasEvidenceAnchor := false
	for _, a := range anchors {
		if evidGet(a, "kind") == "evidence" {
			hasEvidenceAnchor = true
		}
	}
	if !hasEvidenceAnchor {
		f.add("anchor.inclusion", "unverified", []string{"anchor:evidence"}, "the bundle is not anchored")
	}
	for _, av := range anchors {
		a := evM(av)
		ref := []string{"anchor:" + evidStr(a["kind"]) + ":" + evidStr(a["index"])}
		if !anchorable(a["kind"], a["digest"]) {
			f.add("anchor.inclusion", "fail", ref, "the anchor names an artifact that is not this one")
			continue
		}
		g := trust["anchorGuardian"]
		if !evidTruthy(g) {
			f.add("anchor.inclusion", "unverified", ref, "no anchor-log guardian key supplied")
			continue
		}
		h := evM(a["signed_tree_head"])
		proof := evM(a["proof"])
		ok := h["principal"] == EvidenceAnchorLog && evSE(h["instance_id"], evidGet(g, "instance")) && VerifyTreeHead(h, evidStr(evidGet(g, "public")), nil) &&
			evSE(proof["index"], a["index"]) && evSE(proof["size"], h["size"])
		if ok {
			leaf, err := EvidenceAnchorCommitOf(evidStr(a["kind"]), evidStr(a["digest"]))
			ok = err == nil && VerifyLedgerInclusion(evidStr(h["root"]), proof, leaf)
		}
		if ok {
			f.add("anchor.inclusion", "pass", ref, nil)
		} else {
			f.add("anchor.inclusion", "fail", ref, nil)
		}
	}

	// -- attribution: the session-root keys that sign in this bundle must be pinned by the reader
	// Everything above verifies against keys the bundle's own self-signed session root names, so it proves internal consistency
	// only. The revocation authority and the sequencer roots are named inside S, so they are attributed transitively once S's signer
	// is pinned.
	signing := []any{evN(S, "signer"), g0["issuer"]}
	for _, d := range deltas {
		signing = append(signing, evidGet(d, "issuer"))
	}
	for _, a := range evL(b["answers"]) {
		signing = append(signing, evidGet(a, "signer"))
	}
	if evidTruthy(opening) {
		signing = append(signing, evidGet(opening, "principal"))
	}
	keySet := map[string]bool{}
	for _, k := range signing {
		if s, ok := k.(string); ok {
			keySet[s] = true
		}
	}
	keyList := make([]string, 0, len(keySet))
	for k := range keySet {
		keyList = append(keyList, k)
	}
	keys := evSortStrings(keyList)
	attr := evM(summary["attribution"])
	attr["keys_to_check"] = evStrsAny(keys)
	if pinsIn := trust["principals"]; pinsIn == nil {
		f.add("principal.pinned", "unverified", keys, "no pinned principal keys: the bundle names its own principals; verify these keys out of band")
	} else {
		pins := map[string]any{}
		for _, p := range evL(pinsIn) {
			pins[evidStr(evidGet(p, "key"))] = p
		}
		unpinned, mism := []string{}, []string{}
		for _, k := range keys {
			pin, pinned := pins[k]
			if !pinned {
				unpinned = append(unpinned, k)
				continue
			}
			var sp any
			for _, p := range evL(S["principals"]) {
				if evidGet(p, "key") == any(k) {
					sp = p
					break
				}
			}
			if !evEqN(evN(pin, "pq_pk"), evN(sp, "pq_pk")) {
				mism = append(mism, k)
			}
		}
		switch {
		case len(unpinned) > 0:
			f.add("principal.pinned", "fail", unpinned, "signing keys that are not pinned principals")
		case len(mism) > 0:
			f.add("principal.pinned", "fail", mism, "the session root binds a different PQ key than the pin")
		default:
			f.add("principal.pinned", "pass", keys, nil)
			attr["pinned"] = true
		}
	}

	// -- plain-language facts (only what passed)
	proven := []any{}
	passed := func(code string) bool {
		pass, fail := false, false
		for _, x := range f.list {
			if x["code"] == code {
				if x["status"] == "pass" {
					pass = true
				}
				if x["status"] == "fail" {
					fail = true
				}
			}
		}
		return pass && !fail
	}
	pinned := attr["pinned"] == true
	if au, isStr := summary["admitted_under"].(string); isStr && au != "" && passed("pcactn.verify") {
		tag := " (NOT pinned)"
		if pinned {
			tag = " (pinned)"
		}
		proven = append(proven, "The subject action was signed by the agent under "+au+", a grant signed by the session principal"+tag+".")
	}
	if cons := evM(summary["consent"]); cons != nil {
		who := "Session-root key " + evidStr(cons["signer"]) + " (NOT pinned: not attributed to a known principal)"
		if pinned {
			who = "Pinned principal key " + evidStr(cons["signer"])
		}
		proven = append(proven, who+" signed a "+evidStr(cons["tier"])+"-tier \"yes\" bound to this exact action (question "+evidStr(cons["question_id"])+").")
	}
	if ch := evM(summary["charged"]); ch != nil && evF(ch["amount"]) <= evF(ch["bound"]) {
		proven = append(proven, "The charged amount "+evidStr(ch["amount"])+" is within the confirmed value "+evidStr(ch["bound"])+".")
	}
	if rf := evL(summary["refusals"]); len(rf) > 0 {
		ss := make([]string, len(rf))
		for i, x := range rf {
			ss[i] = x.(string)
		}
		proven = append(proven, fmt.Sprintf("The principal refused %d question(s): %s.", len(rf), strings.Join(ss, ", ")))
	}
	if ca := evM(summary["canary_accuracy"]); evF(ca["asked"]) != 0 {
		proven = append(proven, fmt.Sprintf("Canary accuracy %s/%s.", evidStr(ca["correct"]), evidStr(ca["asked"])))
	}
	if passed("accumulator.cap") {
		proven = append(proven, "Every accumulator post is within the cap of the grant that admitted it.")
	}
	if passed("effect.frame") {
		proven = append(proven, "The site reports no change to monitored state outside the write set.")
	}
	summary["proven"] = proven
	_ = n
}

// EvidenceSignedStatement is a COSE Signed Statement (RFC 9943) over the bundle's public reference, ready to register with a SCITT
// Transparency Service: the payload names the bundle by digest and the statement subject defaults to the subject PCActn's digest
// (opts.Subject nil). The bundle itself stays with the site; only its reference is signed. opts.ContentType is always the evidence
// media type.
func EvidenceSignedStatement(bundle any, opts ScittSignStatementOpts) ([]byte, error) {
	ref, err := EvidenceRef(bundle)
	if err != nil {
		return nil, err
	}
	if opts.Subject == nil {
		// `opts.subject ?? ref.subject.pcactn_digest`: an undefined digest leaves the statement without a subject claim
		if d := evidGet(ref["subject"], "pcactn_digest"); d != evidUndef {
			s := evidStr(d)
			opts.Subject = &s
		}
	}
	ct := EvidenceContentType
	opts.ContentType = &ct
	return ScittSignStatement(ref, opts)
}
