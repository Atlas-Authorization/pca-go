package pca

// The judgments of the optimistic path: whether a bonded claim is acceptable (VerifyClaim), whether a fraud proof against it holds
// by independent recomputation (FileFraudProof, VerifyFraudProof), how a dispute over one objective input is settled by an oracle
// (AdjudicateDispute), the bisection game over a trace of such inputs (AdjudicateDisputeGame) and the frozen open-time snapshot
// they all judge on (FreezeOpenSnapshot). Claims, proofs, snapshots and verdicts are JSON objects with the reference's member
// names. Every judgment is total and fails closed: an error is "not fraudulent" / "indeterminate", never a slash.

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
)

// DefaultMinChallengeWindowMs is the realistic floor (30 s) of a challenge window on the store-backed path.
const DefaultMinChallengeWindowMs = 30_000

func oaErrText(r any) string {
	if e, ok := r.(error); ok && e.Error() != "" {
		return e.Error()
	}
	if s, ok := r.(string); ok && s != "" {
		return s
	}
	return "unknown"
}

// oaSame is `a[ka] === b[kb]` for scalar members: an absent member only equals an absent member.
func oaSame(a map[string]any, ka string, b map[string]any, kb string) bool {
	va, ha := a[ka]
	vb, hb := b[kb]
	if ha != hb {
		return false
	}
	return jsStrictEq(va, vb)
}

// VerifyClaim checks a bonded claim against the PCActn it covers: {ok: true} or {ok: false, reason}. The claim must not be for an
// irreversible action, must cover exactly this PCActn, carry a finite claimed_r, sit within the window policy of serverNow (a
// non-finite serverNow means the wall clock; nil policy the default) and be signed by signerPublic. Never panics.
func VerifyClaim(claim any, pcactn map[string]any, signerPublic string, serverNow float64, policy *ChallengeWindowPolicy) (res map[string]any) {
	bad := func(reason string) map[string]any { return map[string]any{"ok": false, "reason": reason} }
	defer func() {
		if r := recover(); r != nil {
			res = bad("claim verification error: " + oaErrText(r))
		}
	}()
	c, ok := extObject(claim)
	if !ok {
		return bad("malformed claim")
	}
	if rc, _ := c["reversibility_class"].(string); rc == irreversibleCls {
		return bad("irreversible action is ineligible for the optimistic path")
	}
	want, err := PCActnDigest(pcactn)
	if err != nil {
		return bad("claim verification error: " + err.Error())
	}
	if d, isStr := c["pcactn_digest"].(string); !isStr || d != want {
		return bad("claim does not cover this PCActn")
	}
	if _, ok := extFinite(c["claimed_r"]); !ok {
		return bad("claimed_r is not finite")
	}
	if !bsFinite(serverNow) {
		serverNow = float64(time.Now().UnixMilli())
	}
	p := DefaultChallengeWindowPolicy
	if policy != nil {
		p = *policy
	}
	if why := ValidateWindow(jsF(c["issued_at"]), jsF(c["challenge_window_ms"]), serverNow, p); why != "" {
		return bad(why)
	}
	body := make(map[string]any, len(c))
	for k, v := range c {
		if k != "sig" {
			body[k] = v
		}
	}
	good, canon := extSignedLenient(signerPublic, claimDomain, body, c["sig"])
	if !canon {
		return bad("claim verification error: the claim is not canonicalizable")
	}
	if !good {
		return bad("claim signature does not verify")
	}
	return map[string]any{"ok": true}
}

func oaMargin(v any) float64 {
	if f, ok := extFinite(v); ok {
		return math.Max(0, f)
	}
	return defaultRMargin
}

func oaMarginPtr(p *float64) float64 {
	if p != nil && bsFinite(*p) {
		return math.Max(0, *p)
	}
	return defaultRMargin
}

// oaWithGrant is {...snapshot, grant}.
func oaWithGrant(snapshot, grant map[string]any) map[string]any {
	out := make(map[string]any, len(snapshot)+1)
	for k, v := range snapshot {
		out[k] = v
	}
	out["grant"] = grant
	return out
}

type oaSummary struct {
	release, optimistic bool
	r                   float64
}

func (s oaSummary) json() map[string]any {
	return map[string]any{"releaseGuardianShare": s.release, "r": bsNum(s.r), "optimisticAllowed": s.optimistic}
}

func (s oaSummary) admits(claimedR, margin float64) bool {
	return s.release && s.optimistic && s.r <= claimedR+margin
}

func oaSummarize(d map[string]any) oaSummary {
	rt, _ := d["requiredThreshold"].(map[string]any)
	return oaSummary{release: d["releaseGuardianShare"] == true, optimistic: rt["optimisticAllowed"] == true, r: jsF(d["r"])}
}

func oaReasons(d map[string]any) string {
	list, _ := d["reasons"].([]any)
	parts := make([]string, 0, len(list))
	for _, x := range list {
		s, _ := x.(string)
		parts = append(parts, s)
	}
	if s := strings.Join(parts, "; "); s != "" {
		return s
	}
	return "not compliant"
}

func oaActionClass(snapshot map[string]any) any {
	a, _ := snapshot["action"].(map[string]any)
	inner, _ := a["action"].(map[string]any)
	return inner["reversibility_class"]
}

// FileFraudProof builds a fraud proof against a claim from the frozen open-time snapshot (the Decide input without the grant
// matters: the verifier supplies its own grant). It returns nil when there is no snapshot, when the claim does not cover the
// PCActn, or when the recomputed decision is compliant: there is nothing to prove. kind is irreversible, policy-denied,
// optimistic-not-allowed or risk-understated.
func FileFraudProof(claim, pcactn, grant, openSnapshot map[string]any, rMargin *float64) map[string]any {
	if openSnapshot == nil {
		return nil
	}
	actual := Decide(oaWithGrant(openSnapshot, grant))
	digest, err := PCActnDigest(pcactn)
	if d, isStr := claim["pcactn_digest"].(string); err != nil || !isStr || d != digest {
		return nil // cannot frame a different action
	}
	margin := oaMarginPtr(rMargin)
	s := oaSummarize(actual)
	evidence := make(map[string]any, len(openSnapshot))
	for k, v := range openSnapshot {
		if k != "grant" {
			evidence[k] = v
		}
	}
	rt, _ := actual["requiredThreshold"].(map[string]any)
	pa, _ := pcactn["action"].(map[string]any)
	claimedR := jsF(claim["claimed_r"])
	kind, reason := "", ""
	switch {
	case claim["reversibility_class"] == irreversibleCls || pa["reversibility_class"] == irreversibleCls:
		kind, reason = "irreversible", "irreversible action took the optimistic path"
	case !s.release:
		kind, reason = "policy-denied", "Policy VM denied the action: "+oaReasons(actual)
	case !s.optimistic:
		kind, reason = "optimistic-not-allowed", fmt.Sprintf("optimistic path not allowed at real r=%s (t=%s)", rsToFixed(s.r, 3), rsNumStr(jsF(rt["t"])))
	case s.r > claimedR+margin:
		kind, reason = "risk-understated", fmt.Sprintf("claimed r=%s but real r=%s", rsNumStr(claimedR), rsToFixed(s.r, 3))
	default:
		return nil
	}
	out := map[string]any{"decision": s.json(), "evidence": evidence, "r_margin": bsNum(margin), "kind": kind, "reason": reason}
	bsPut(out, "pcactn_digest", claim, "pcactn_digest")
	bsPut(out, "bond_ref", claim, "bond_ref")
	bsPut(out, "claimed_r", claim, "claimed_r")
	return out
}

// VerifyFraudProof judges a fraud proof by INDEPENDENT recomputation over the frozen open-time snapshot and the verifier's own
// grant: {fraudulent, slashBondRef?, reason}. The proof's own decision is only checked for agreement, never trusted. A proof for
// another PCActn or bond, a missing snapshot, or any error is not fraudulent. Never panics.
func VerifyFraudProof(claim map[string]any, proof any, grant map[string]any, openSnapshot any) (res map[string]any) {
	no := func(reason string) map[string]any { return map[string]any{"fraudulent": false, "reason": reason} }
	defer func() {
		if r := recover(); r != nil {
			res = no("fraud-proof verification error: " + oaErrText(r))
		}
	}()
	p, ok := extObject(proof)
	if !ok {
		return no("malformed fraud proof")
	}
	if !oaSame(p, "pcactn_digest", claim, "pcactn_digest") {
		return no("fraud proof targets a different PCActn than the claim")
	}
	if !oaSame(p, "bond_ref", claim, "bond_ref") {
		return no("fraud proof names a different bond than the claim")
	}
	snap, ok := extObject(openSnapshot)
	if !ok {
		return no("no frozen open-time snapshot supplied; cannot judge the claim")
	}
	recomputed := Decide(oaWithGrant(snap, grant))
	s := oaSummarize(recomputed)
	pd, isObj := p["decision"].(map[string]any)
	if !isObj {
		kind := "undefined"
		if v, has := p["decision"]; has && v == nil {
			kind = "null"
		}
		return no("fraud-proof verification error: Cannot read properties of " + kind + " (reading 'releaseGuardianShare')")
	}
	if !jsStrictEq(pd["releaseGuardianShare"], s.release) || !jsStrictEq(pd["optimisticAllowed"], s.optimistic) || math.Abs(s.r-jsF(pd["r"])) > 1e-9 {
		return no("proof decision does not match an independent recomputation")
	}
	margin := oaMargin(p["r_margin"])
	yes := func(reason string) map[string]any {
		out := map[string]any{"fraudulent": true, "reason": reason}
		bsPut(out, "slashBondRef", claim, "bond_ref")
		return out
	}
	claimedR := jsF(claim["claimed_r"])
	switch {
	case claim["reversibility_class"] == irreversibleCls || oaActionClass(snap) == irreversibleCls:
		return yes("irreversible action is ineligible for the optimistic path")
	case !s.release:
		return yes("Policy VM denies the action: " + oaReasons(recomputed))
	case !s.optimistic:
		return yes("optimistic path not allowed at real r=" + rsToFixed(s.r, 3))
	case s.r > claimedR+margin:
		return yes(fmt.Sprintf("risk understated: claimed %s, real %s", rsNumStr(claimedR), rsToFixed(s.r, 3)))
	}
	return no("claim is compliant under independent recomputation; bond stands")
}

// ObjectiveOracle resolves one disputed input (reversibility_class, reversibility, blastRadius or semanticDistance) for a frozen
// snapshot: {input, value? | class?, valid, reason?}. nil, another input or valid != true means it could not resolve
// authoritatively, which settles nothing (fail closed).
type ObjectiveOracle func(input string, snapshot map[string]any) map[string]any

func oaDisputable(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok && (s == "reversibility_class" || s == "reversibility" || s == "blastRadius" || s == "semanticDistance")
}

// oaVal is a possibly absent JSON value (JavaScript undefined is has == false).
type oaVal struct {
	v   any
	has bool
}

func oaGet(m map[string]any, k string) oaVal {
	v, has := m[k]
	return oaVal{v, has && m != nil}
}

// text is JSON.stringify of the value inside a template literal.
func (x oaVal) text() string {
	if !x.has {
		return "undefined"
	}
	switch t := x.v.(type) {
	case nil:
		return "null"
	case string:
		return bsQuote(t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	}
	if f, ok := jsNum(x.v); ok {
		if !bsFinite(f) {
			return "null"
		}
		return rsNumStr(f)
	}
	b, _ := json.Marshal(x.v)
	return string(b)
}

func (x oaVal) put(m map[string]any, k string) {
	if x.has {
		m[k] = x.v
	}
}

func oaSnapshotValue(snap map[string]any, input string) oaVal {
	if input == "reversibility_class" {
		cc, _ := snap["caveatContext"].(map[string]any)
		if v := oaGet(cc, "reversibilityClass"); v.has && v.v != nil {
			return v
		}
		a, _ := snap["action"].(map[string]any)
		inner, _ := a["action"].(map[string]any)
		return oaGet(inner, "reversibility_class")
	}
	risk, _ := snap["risk"].(map[string]any)
	return oaGet(risk, input)
}

// oaSubstitute returns the snapshot with the disputed input replaced by the oracle's (or a party's) value; it panics with the
// reference's message when the resolution carries no usable value.
func oaSubstitute(snap map[string]any, input string, value, class oaVal) map[string]any {
	next := copyMap(snap)
	cc, hasCC := snap["caveatContext"].(map[string]any)
	if input == "reversibility_class" {
		cls, isStr := class.v.(string)
		if !class.has || !isStr || cls == "" {
			panic("oracle reversibility_class resolution carries no class")
		}
		a, _ := snap["action"].(map[string]any)
		inner, _ := a["action"].(map[string]any)
		na, ni := copyMap(a), copyMap(inner)
		if na == nil {
			na = map[string]any{}
		}
		if ni == nil {
			ni = map[string]any{}
		}
		ni["reversibility_class"] = cls
		na["action"] = ni
		next["action"] = na
		if v, has := cc["reversibilityClass"]; hasCC && has && v != nil {
			nc := copyMap(cc)
			nc["reversibilityClass"] = cls
			next["caveatContext"] = nc
		}
		return next
	}
	f, ok := extFinite(value.v)
	if !value.has || !ok {
		panic("oracle " + input + " resolution carries no finite value")
	}
	risk, _ := snap["risk"].(map[string]any)
	nr := copyMap(risk)
	if nr == nil {
		nr = map[string]any{}
	}
	nr[input] = bsNum(f)
	next["risk"] = nr
	if v, has := cc["blastRadius"]; input == "blastRadius" && hasCC && has && v != nil {
		nc := copyMap(cc)
		nc["blastRadius"] = bsNum(f)
		next["caveatContext"] = nc
	}
	return next
}

var oaWorst = oaSummary{release: false, r: 1, optimistic: false}

func oaIndeterminate(input, reason string, baseline oaSummary, agent oaVal) map[string]any {
	out := map[string]any{"outcome": "indeterminate", "fraudulent": false, "slashCounterBond": false, "input": input,
		"baseline": baseline.json(), "adjudicated": oaWorst.json(), "reason": reason}
	agent.put(out, "agentValue")
	return out
}

// AdjudicateDispute settles a dispute over ONE objective input of a claim: the oracle's value replaces the agent's in the frozen
// open-time snapshot and the decision is recomputed. The verdict {outcome, fraudulent, slashBondRef?, slashCounterBond, input,
// agentValue?, oracleValue?, baseline, adjudicated, reason} is agent-fraud (the fast-path admission does not survive: slash the
// agent's bond), claim-upheld (it survives: the dispute was frivolous, slash the challenger's counter-bond) or indeterminate (the
// oracle could not resolve, or anything is malformed: slash neither). Never panics.
func AdjudicateDispute(claim map[string]any, dispute any, grant map[string]any, openSnapshot any, oracle ObjectiveOracle, rMargin *float64) (res map[string]any) {
	margin := oaMarginPtr(rMargin)
	fallbackInput := "reversibility_class"
	defer func() {
		if r := recover(); r != nil {
			res = oaIndeterminate(fallbackInput, "dispute adjudication error (fail closed): "+oaErrText(r), oaWorst, oaVal{})
		}
	}()
	d, ok := extObject(dispute)
	if !ok {
		return oaIndeterminate("reversibility_class", "malformed dispute", oaWorst, oaVal{})
	}
	input, known := oaDisputable(d["input"])
	if !known {
		return oaIndeterminate("reversibility_class", "unknown disputed input: "+oaString(oaGet(d, "input")), oaWorst, oaVal{})
	}
	fallbackInput = input
	if !oaSame(d, "pcactn_digest", claim, "pcactn_digest") {
		return oaIndeterminate(input, "dispute targets a different PCActn than the claim", oaWorst, oaVal{})
	}
	if !oaSame(d, "bond_ref", claim, "bond_ref") {
		return oaIndeterminate(input, "dispute names a different bond than the claim", oaWorst, oaVal{})
	}
	os, ok := extObject(openSnapshot)
	if !ok {
		return oaIndeterminate(input, "no frozen open-time snapshot supplied; cannot adjudicate", oaWorst, oaVal{})
	}
	if oracle == nil {
		return oaIndeterminate(input, "no objective oracle supplied", oaWorst, oaVal{})
	}
	snap := oaWithGrant(os, grant)
	baseline := oaSummarize(Decide(snap))
	agent := oaSnapshotValue(snap, input)
	r := oracle(input, snap)
	if r == nil || r["input"] != any(input) || !jsTruthy(r["valid"]) {
		why := "objective oracle could not authoritatively resolve " + input
		if r != nil && jsTruthy(r["reason"]) {
			why += ": " + oaString(oaGet(r, "reason"))
		}
		return oaIndeterminate(input, why, baseline, agent)
	}
	oracleValue := oaGet(r, "class")
	if !oracleValue.has || oracleValue.v == nil {
		oracleValue = oaGet(r, "value")
	}
	adjudicated := oaSummarize(Decide(oaSubstitute(snap, input, oaGet(r, "value"), oaGet(r, "class"))))
	out := map[string]any{"input": input, "baseline": baseline.json(), "adjudicated": adjudicated.json()}
	agent.put(out, "agentValue")
	oracleValue.put(out, "oracleValue")
	claimedR := jsF(claim["claimed_r"])
	if !adjudicated.admits(claimedR, margin) {
		why := fmt.Sprintf("the real r=%s exceeds the claimed r=%s", rsToFixed(adjudicated.r, 3), oaString(oaGet(claim, "claimed_r")))
		if !adjudicated.release {
			why = "the Policy VM denies the action"
		} else if !adjudicated.optimistic {
			why = "the optimistic path is not allowed (higher threshold) at r=" + rsToFixed(adjudicated.r, 3)
		}
		out["outcome"], out["fraudulent"], out["slashCounterBond"] = "agent-fraud", true, false
		bsPut(out, "slashBondRef", claim, "bond_ref")
		out["reason"] = fmt.Sprintf("understated %s: agent relied on %s, oracle says %s — %s", input, agent.text(), oracleValue.text(), why)
		return out
	}
	out["outcome"], out["fraudulent"], out["slashCounterBond"] = "claim-upheld", false, true
	out["reason"] = fmt.Sprintf("the objective oracle upholds the agent's %s (%s); fast-path admission survives — the dispute is frivolous", input, oracleValue.text())
	return out
}

// oaString is String(value).
func oaString(x oaVal) string {
	if !x.has {
		return "undefined"
	}
	if s, ok := x.v.(string); ok {
		return s
	}
	if _, isMap := x.v.(map[string]any); isMap {
		return "[object Object]"
	}
	return x.text()
}

// oaAssertion is one party's value for one step: {value?} or {class?}.
type oaAssertion struct{ value, class oaVal }

func oaAssertionOf(v any) (oaAssertion, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return oaAssertion{}, false
	}
	return oaAssertion{oaGet(m, "value"), oaGet(m, "class")}, true
}

func (a oaAssertion) equals(b oaAssertion) bool {
	valueEq := !a.value.has && !b.value.has
	if !valueEq {
		fa, oka := jsNum(a.value.v)
		fb, okb := jsNum(b.value.v)
		// Object.is: NaN equals NaN, +0 and -0 differ
		valueEq = a.value.has && b.value.has && oka && okb && ((fa == fb && math.Signbit(fa) == math.Signbit(fb)) || (math.IsNaN(fa) && math.IsNaN(fb)))
	}
	return valueEq && a.class.has == b.class.has && jsStrictEq(a.class.v, b.class.v)
}

func oaStateAfter(snap map[string]any, steps []string, as []oaAssertion) oaSummary {
	s := snap
	for i, input := range steps {
		s = oaSubstitute(s, input, as[i].value, as[i].class)
	}
	return oaSummarize(Decide(s))
}

// AdjudicateDisputeGame settles a dispute over a TRACE of objective inputs by bisection: both parties commit a full assertion
// trace (game = {pcactn_digest, bond_ref, steps, defender, challenger}), the first step where they differ is found in
// log2(steps) rounds, and only that one step goes to the oracle (AdjudicateDispute on the agreed pre-state). The result is
// {verdict, converged, contestedStep, contestedInput?, transcript, rounds}; a malformed game, identical traces, or parties that do
// not actually disagree on admission give an indeterminate verdict with converged false. Never panics.
func AdjudicateDisputeGame(claim map[string]any, game any, grant map[string]any, openSnapshot any, oracle ObjectiveOracle, rMargin *float64) (res map[string]any) {
	margin := oaMarginPtr(rMargin)
	g, _ := game.(map[string]any)
	rawSteps, _ := g["steps"].([]any)
	fail := func(reason string, input string) map[string]any {
		if input == "" {
			input = "reversibility_class"
			if len(rawSteps) > 0 {
				if s, ok := oaDisputable(rawSteps[0]); ok {
					input = s
				}
			}
		}
		return map[string]any{"verdict": oaIndeterminate(input, reason, oaWorst, oaVal{}), "converged": false, "contestedStep": jsNumber(-1),
			"transcript": []any{}, "rounds": jsNumber(0)}
	}
	defer func() {
		if r := recover(); r != nil {
			res = fail("dispute game adjudication error (fail closed): "+oaErrText(r), "")
		}
	}()
	if g == nil {
		return fail("malformed dispute game", "")
	}
	if !oaSame(g, "pcactn_digest", claim, "pcactn_digest") {
		return fail("dispute game targets a different PCActn than the claim", "")
	}
	if !oaSame(g, "bond_ref", claim, "bond_ref") {
		return fail("dispute game names a different bond than the claim", "")
	}
	if len(rawSteps) < 1 {
		return fail("dispute game has no steps", "")
	}
	steps := make([]string, len(rawSteps))
	for i, s := range rawSteps {
		name, ok := oaDisputable(s)
		if !ok {
			return fail("unknown disputed input: "+oaString(oaVal{s, true}), "")
		}
		steps[i] = name
	}
	rawDef, okD := g["defender"].([]any)
	rawCh, okC := g["challenger"].([]any)
	if !okD || !okC || len(rawDef) != len(steps) || len(rawCh) != len(steps) {
		return fail("party assertions do not cover every step", "")
	}
	os, ok := extObject(openSnapshot)
	if !ok {
		return fail("no frozen open-time snapshot supplied; cannot adjudicate", "")
	}
	if oracle == nil {
		return fail("no objective oracle supplied", "")
	}
	n := len(steps)
	defender, challenger := make([]oaAssertion, n), make([]oaAssertion, n)
	for i := 0; i < n; i++ {
		var okA, okB bool
		defender[i], okA = oaAssertionOf(rawDef[i])
		challenger[i], okB = oaAssertionOf(rawCh[i])
		if !okA || !okB {
			return fail("dispute game adjudication error (fail closed): dispute game trace is shorter than its step list", "")
		}
	}
	snap := oaWithGrant(os, grant)
	claimedR := jsF(claim["claimed_r"])
	if !oaStateAfter(snap, steps, defender).admits(claimedR, margin) {
		return fail("defender does not defend the fast-path admission; nothing to adjudicate", "")
	}
	if oaStateAfter(snap, steps, challenger).admits(claimedR, margin) {
		return fail("the parties do not disagree on admission; no genuine dispute to bisect", "")
	}
	prefixAgrees := func(m int) bool {
		for i := 0; i < m; i++ {
			if !defender[i].equals(challenger[i]) {
				return false
			}
		}
		return true
	}
	if prefixAgrees(n) {
		return fail("the parties committed identical traces; no contested step to bisect", "")
	}
	lo, hi := 0, n
	transcript := []any{}
	for hi-lo > 1 {
		mid := (lo + hi) / 2
		agreed := prefixAgrees(mid)
		transcript = append(transcript, map[string]any{"lo": jsNumber(float64(lo)), "hi": jsNumber(float64(hi)), "mid": jsNumber(float64(mid)), "agreedAtMid": agreed})
		if agreed {
			lo = mid
		} else {
			hi = mid
		}
	}
	contested := lo // prefixAgrees(lo) holds and prefixAgrees(lo+1) does not: step lo is the first to differ
	input := steps[contested]
	pre := snap
	for i := 0; i < contested; i++ {
		pre = oaSubstitute(pre, steps[i], defender[i].value, defender[i].class)
	}
	move := challenger[contested]
	dispute := map[string]any{"input": input}
	bsPut(dispute, "pcactn_digest", claim, "pcactn_digest")
	bsPut(dispute, "bond_ref", claim, "bond_ref")
	move.value.put(dispute, "asserted_value")
	move.class.put(dispute, "asserted_class")
	verdict := AdjudicateDispute(claim, dispute, grant, pre, oracle, &margin)
	return map[string]any{"verdict": verdict, "converged": true, "contestedStep": jsNumber(float64(contested)), "contestedInput": input,
		"transcript": transcript, "rounds": jsNumber(float64(len(transcript)))}
}

// FreezeOpenSnapshot returns a deep copy of a Decide input as it stood when the claim opened (a JSON round trip: members JSON
// cannot carry are dropped). Judge fraud proofs and disputes on this copy, never on live state.
func FreezeOpenSnapshot(input map[string]any) (map[string]any, error) {
	b, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	v, err := ParseJSONLenient(b)
	if err != nil {
		return nil, err
	}
	m, _ := normalizeJSON(v).(map[string]any)
	return m, nil
}
