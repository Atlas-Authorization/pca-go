package pca

// Property-based machine-checking of the core safety invariants (attenuation monotonicity, budget soundness, fail-closed
// behaviour, determinism) against the real core, plus the generators they draw from. The generators run over a small
// deterministic SplitMix64 generator (the reference uses a property-testing library with its own generator and shrinking;
// neither is reproduced, so a given seed explores different cases than the reference). A property is `func(*InvRng) bool`;
// CheckInvariants runs each one numRuns times from a fixed seed and reports a failing case's seed so it can be replayed.

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// InvRng is a deterministic SplitMix64 generator: the same seed always yields the same stream.
type InvRng struct{ s uint64 }

// NewInvRng seeds a generator.
func NewInvRng(seed uint64) *InvRng { return &InvRng{s: seed} }

// U64 is the next 64 random bits.
func (r *InvRng) U64() uint64 {
	r.s += 0x9e3779b97f4a7c15
	z := r.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// Float is uniform in [0, 1).
func (r *InvRng) Float() float64 { return float64(r.U64()>>11) / (1 << 53) }

// Int is uniform in [lo, hi] inclusive.
func (r *InvRng) Int(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	return lo + int(r.U64()%uint64(hi-lo+1))
}

// Bool is a fair coin.
func (r *InvRng) Bool() bool { return r.U64()&1 == 1 }

// Dbl is a double in [lo, hi], the endpoints included on purpose.
func (r *InvRng) Dbl(lo, hi float64) float64 {
	x := r.Float()
	switch {
	case x < 0.08:
		return lo
	case x < 0.16:
		return hi
	}
	return lo + float64((hi-lo)*r.Float())
}

func invPick[T any](r *InvRng, xs []T) T { return xs[r.Int(0, len(xs)-1)] }

func invString(r *InvRng, lo, hi int) string {
	n := r.Int(lo, hi)
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Int(0x20, 0x7e))
	}
	return string(b)
}

func invArray[T any](r *InvRng, gen func(*InvRng) T, lo, hi int) []T {
	n := r.Int(lo, hi)
	out := make([]T, n)
	for i := range out {
		out[i] = gen(r)
	}
	return out
}

func invNum(i int) any { return jsNumber(float64(i)) }

// InvArbSeed32 is 32 random bytes: a reproducible Ed25519 secret seed.
func InvArbSeed32(r *InvRng) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(r.U64())
	}
	return b
}

var (
	invVerbs     = []string{"read", "write", "delete", "transfer", "list", "admin"}
	invResources = []string{"/acct/a", "/acct/b", "/docs/1", "/docs/2", "/x/y", "/"}
	invLeafOps   = []string{"eq", "ne", "in", "nin", "lt", "lte", "gt", "gte", "prefix", "exists"}
	invFields    = []string{"subject.role", "subject.tier", "env.ip", "action.verb", "action.resource", "action.params.amount"}
)

func invArbVerb(r *InvRng) string { return invPick(r, invVerbs) }

func invArbResource(r *InvRng) string {
	if r.Float() < 0.5 {
		return invPick(r, invResources)
	}
	return invString(r, 0, 10)
}

// InvArbLeafCondition is a random leaf condition {field, op, value}.
func InvArbLeafCondition(r *InvRng) map[string]any {
	var v any
	switch r.Int(0, 3) {
	case 0:
		v = invString(r, 0, 10)
	case 1:
		v = float64(r.Int(-10, 10))
	case 2:
		v = r.Bool()
	default:
		v = invToAny(invArray(r, func(r *InvRng) string { return invString(r, 0, 10) }, 0, 3))
	}
	return map[string]any{"field": invPick(r, invFields), "op": invPick(r, invLeafOps), "value": v}
}

func invToAny[T any](xs []T) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

// InvArbPredicate is a random predicate {verb, resource?, where?}.
func InvArbPredicate(r *InvRng) map[string]any {
	var verb any
	switch r.Int(0, 2) {
	case 0:
		verb = invArbVerb(r)
	case 1:
		verb = invToAny(invArray(r, func(r *InvRng) string { return invArbVerb(r) }, 1, 3))
	default:
		verb = "*"
	}
	p := map[string]any{"verb": verb}
	switch r.Int(0, 3) {
	case 1:
		p["resource"] = "*"
	case 2:
		p["resource"] = invPick(r, []string{"/acct/*", "/docs/*"})
	case 3:
		p["resource"] = invArbResource(r)
	}
	if r.Float() < 0.5 {
		p["where"] = invToAny(invArray(r, InvArbLeafCondition, 0, 2))
	}
	return p
}

// InvArbPredicateList is 1-4 random predicates.
func InvArbPredicateList(r *InvRng) []any { return invToAny(invArray(r, InvArbPredicate, 1, 4)) }

// InvArbActionContext is a random {action, subject?, env?} context.
func InvArbActionContext(r *InvRng) map[string]any {
	action := map[string]any{"verb": invArbVerb(r), "resource": invArbResource(r)}
	if r.Float() < 0.5 {
		params := map[string]any{}
		keys := []string{"amount", "target", "reason"}
		for i := r.Int(0, 3); i > 0 && len(keys) > 0; i-- {
			j := r.Int(0, len(keys)-1)
			k := keys[j]
			keys = append(keys[:j], keys[j+1:]...)
			switch r.Int(0, 2) {
			case 0:
				params[k] = invString(r, 0, 10)
			case 1:
				params[k] = float64(r.Int(-5, 100))
			default:
				params[k] = r.Bool()
			}
		}
		action["params"] = params
	}
	ctx := map[string]any{"action": action}
	role, tier, ip := invPick(r, []string{"admin", "user", "guest"}), r.Int(0, 5), invString(r, 0, 10)
	if r.Float() < 0.5 {
		ctx["subject"] = map[string]any{"role": role, "tier": float64(tier)}
	}
	if r.Float() < 0.5 {
		ctx["env"] = map[string]any{"ip": ip}
	}
	return ctx
}

// InvArbCaveatContext is a random caveat evaluation context (snake_case keys).
func InvArbCaveatContext(r *InvRng) map[string]any {
	ctx := map[string]any{"now": float64(r.Int(0, 10_000_000))}
	if r.Float() < 0.5 {
		ctx["blast_radius"] = r.Dbl(0, 1)
	}
	if r.Float() < 0.5 {
		ctx["reversibility_class"] = invPick(r, []string{"reversible", "rate_limited", "irreversible", "teleport"})
	}
	if r.Float() < 0.5 {
		ctx["delegation_depth"] = float64(r.Int(0, 20))
	}
	if r.Float() < 0.5 {
		ctx["recent_action_times"] = invToAny(invArray(r, func(r *InvRng) float64 { return float64(r.Int(0, 10_000_000)) }, 0, 6))
	}
	return ctx
}

// InvEvalPoint is an action context and a caveat context together: one point at which to probe a chain's authority.
type InvEvalPoint struct{ Action, CavCtx map[string]any }

// InvArbEvalPoint is a random probe point.
func InvArbEvalPoint(r *InvRng) InvEvalPoint {
	return InvEvalPoint{Action: InvArbActionContext(r), CavCtx: InvArbCaveatContext(r)}
}

// InvArbCaveatSpec is a random caveat spec as InvariantBuildChain takes it.
func InvArbCaveatSpec(r *InvRng) map[string]any {
	switch r.Int(0, 6) {
	case 0:
		return map[string]any{"k": "expires", "at": invNum(r.Int(0, 10_000_000))}
	case 1:
		return map[string]any{"k": "not_before", "at": invNum(r.Int(0, 10_000_000))}
	case 2:
		return map[string]any{"k": "rate", "max": invNum(r.Int(1, 10)), "per_secs": invNum(r.Int(1, 3600))}
	case 3: // quantized to 3 decimals so the limit is canonical-wire-safe
		return map[string]any{"k": "max_blast_radius", "max": jsNumber(float64(r.Int(0, 1000)) / 1000)}
	case 4:
		return map[string]any{"k": "reversibility_max", "cls": invPick(r, []string{"reversible", "rate_limited", "irreversible"})}
	case 5:
		return map[string]any{"k": "delegation_depth", "max": invNum(r.Int(0, 20))}
	}
	return map[string]any{"k": "budget_frac", "frac": jsNumber(r.Dbl(0, 1))}
}

// InvArbChain is a random signed, legally attenuating chain of up to 6 capabilities.
func InvArbChain(r *InvRng) (*InvariantChain, error) {
	m := InvariantChainModel{PrincipalSeed: InvArbSeed32(r), Holder0Seed: InvArbSeed32(r),
		RootSpecs: invArray(r, InvArbCaveatSpec, 1, 4)}
	m.Hops = invArray(r, func(r *InvRng) InvariantHop {
		return InvariantHop{HolderSeed: InvArbSeed32(r), AddedSpecs: invArray(r, InvArbCaveatSpec, 0, 3)}
	}, 0, 5)
	m.Predicates = InvArbPredicateList(r)
	return InvariantBuildChain(m)
}

// InvArbRiskPolicy is a well-formed risk policy: kappa > 0, 0 <= theta1 <= theta2, the rest finite >= 0.
func InvArbRiskPolicy(r *InvRng) RiskPolicy {
	w := RiskWeights{Alpha: r.Dbl(0, 2), Beta: r.Dbl(0, 2), Gamma: r.Dbl(0, 2), Delta: r.Dbl(0, 2), Epsilon: r.Dbl(0, 2), Zeta: r.Dbl(0, 2)}
	t1 := r.Dbl(0, 1)
	return RiskPolicy{Weights: w, Theta1: t1, Theta2: t1 + r.Dbl(0, 1), Kappa: r.Dbl(0.001, 5), Lambda: r.Dbl(0, 0.01), Rho: r.Dbl(0, 2), BMax: r.Dbl(0, 10)}
}

// InvArbRiskInputs is a random risk input, every axis in [0, 1].
func InvArbRiskInputs(r *InvRng) RiskInputs {
	return RiskInputs{SemanticDistance: r.Dbl(0, 1), Reversibility: r.Dbl(0, 1), BlastRadius: r.Dbl(0, 1), Taint: r.Dbl(0, 1), Confidence: r.Dbl(0, 1), Age: r.Dbl(0, 1)}
}

// InvArbTrustBudget is a random trust budget.
func InvArbTrustBudget(r *InvRng) TrustBudget {
	b := TrustBudget{B: r.Dbl(0, 10), Tau: float64(r.Int(0, 10_000_000))}
	if r.Float() < 0.5 {
		b.AsOf, b.HasAsOf = float64(r.Int(0, 10_000_000)), true
	}
	return b
}

func invWorsen(b RiskInputs, r *InvRng) RiskInputs {
	return RiskInputs{
		SemanticDistance: invClamp01(b.SemanticDistance + r.Dbl(0, 1)), BlastRadius: invClamp01(b.BlastRadius + r.Dbl(0, 1)),
		Taint: invClamp01(b.Taint + r.Dbl(0, 1)), Age: invClamp01(b.Age + r.Dbl(0, 1)),
		Reversibility: invClamp01(b.Reversibility - r.Dbl(0, 1)), Confidence: invClamp01(b.Confidence - r.Dbl(0, 1)),
	}
}

// InvProp is a property: true when the generated case upholds the invariant.
type InvProp func(r *InvRng) bool

const invEps = 1e-9

func invCaps(c *InvariantChain) []any {
	out := make([]any, len(c.Caps))
	for i, x := range c.Caps {
		out[i] = x
	}
	return out
}

func invCapCaveats(cap any) []any {
	m, _ := cap.(map[string]any)
	l, _ := m["caveats"].([]any)
	return l
}

func invAuthAllowed(caveats []any, predicates []any, p InvEvalPoint) bool {
	if !evaluatePredicates(predicates, p.Action) {
		return false
	}
	ok, _ := EvaluateCaveats(caveats, p.CavCtx)
	return ok
}

func invVerifies(caps []any, root string) bool { _, ok := VerifyChain(caps, root, true); return ok }

func invHash(v any) string { h, _ := HashCanonical(v); return h }

// InvAttenuationMonotonicity: a legal chain verifies; each hop's caveats extend its parent's append-only; budget_alloc limits never
// grow; and at every probe point the per-hop verdict is monotone non-increasing root to leaf.
func InvAttenuationMonotonicity(r *InvRng) bool {
	chain, err := InvArbChain(r)
	if err != nil {
		return false
	}
	points := invArray(r, InvArbEvalPoint, 1, 5)
	caps := invCaps(chain)
	if !invVerifies(caps, chain.RootIssuer) {
		return false
	}
	for i := 1; i < len(caps); i++ {
		parent, child := invCapCaveats(caps[i-1]), invCapCaveats(caps[i])
		if len(child) < len(parent) {
			return false
		}
		for j := range parent {
			if invHash(child[j]) != invHash(parent[j]) {
				return false
			}
		}
	}
	leaf := invCapCaveats(caps[len(caps)-1])
	if _, ok := allocationsMonotone(leaf); !ok {
		return false
	}
	prev, have := 0.0, false
	for _, cv := range leaf {
		m, _ := cv.(map[string]any)
		if m["type"] != "budget_alloc" {
			continue
		}
		lim, ok := jsNum(m["limit"])
		if !ok {
			continue
		}
		if have && lim > prev {
			return false
		}
		prev, have = lim, true
	}
	preds := chain.Predicates.([]any)
	for _, pt := range points {
		ancestor := true
		for _, c := range caps {
			allowed := invAuthAllowed(invCapCaveats(c), preds, pt)
			if allowed && !ancestor { // a true after a false would be a widening
				return false
			}
			ancestor = allowed
		}
	}
	return true
}

// InvRiskMonotone: r is clamped to [0, 1] and a pointwise-worse input never yields a lower r.
func InvRiskMonotone(r *InvRng) bool {
	policy, inputs := InvArbRiskPolicy(r), InvArbRiskInputs(r)
	s := RiskScore(inputs, policy.Weights)
	if !(s >= 0 && s <= 1) {
		return false
	}
	w := RiskScore(invWorsen(inputs, r), policy.Weights)
	return w >= 0 && w <= 1 && w+invEps >= s
}

// InvAdmissionSoundness: whenever Admit lets an action proceed without a human the admitted cost is covered by the budget, and the
// safety bound is exactly bMax/kappa.
func InvAdmissionSoundness(r *InvRng) bool {
	policy, inputs, budget := InvArbRiskPolicy(r), InvArbRiskInputs(r), InvArbTrustBudget(r)
	if ValidateRiskPolicy(policy) != "" {
		return false
	}
	s := RiskScore(inputs, policy.Weights)
	c := RiskCost(s, policy.Kappa)
	adm := Admit(s, budget, policy)
	if adm.Metered && (adm.T >= 3 || !(budget.B+invEps >= c)) {
		return false
	}
	if adm.Admit && (adm.T != 1 || !adm.Metered || !(budget.B+invEps >= c)) {
		return false
	}
	expected := 0.0
	if policy.Kappa > 0 {
		expected = math.Max(0, policy.BMax) / policy.Kappa
	}
	return math.Abs(SafetyBound(policy.BMax, policy.Kappa)-expected) <= invEps
}

// InvCumulativeBudgetBound: any sequence of machine-only actions debiting kappa*r never drives B negative and the total admitted risk
// obeys Sum(r) <= bMax/kappa.
func InvCumulativeBudgetBound(r *InvRng) bool {
	policy := InvArbRiskPolicy(r)
	seq := invArray(r, InvArbRiskInputs, 1, 40)
	bound := SafetyBound(policy.BMax, policy.Kappa)
	b, sum := math.Max(0, policy.BMax), 0.0
	for _, in := range seq {
		s := RiskScore(in, policy.Weights)
		adm := Admit(s, TrustBudget{B: b, HasAsOf: true}, policy)
		if adm.Metered && adm.T < 3 {
			c := RiskCost(s, policy.Kappa)
			if !(b+invEps >= c) {
				return false
			}
			b = math.Max(0, b-c)
			sum += s
			if b < -invEps || !(policy.Kappa*sum <= policy.BMax+1e-6) || !(sum <= bound+1e-6) {
				return false
			}
		}
	}
	return true
}

var invUndecidables = []func(f string) map[string]any{
	func(f string) map[string]any {
		return map[string]any{"field": f + ".definitely_absent", "op": "eq", "value": "x"}
	},
	func(f string) map[string]any { return map[string]any{"field": f, "op": "lt", "value": 5.0} },
	func(f string) map[string]any { return map[string]any{"field": f, "op": "in", "value": "not-an-array"} },
	func(f string) map[string]any { return map[string]any{"field": f, "op": "eq"} },
	func(f string) map[string]any {
		return map[string]any{"field": f, "op": "member_of", "value": "g", "collection": "env.no_such_collection"}
	},
}

func invTri(c any, ctx map[string]any) int { return evaluateConditionTri(c, ctx, &regexBudget{}) }

// InvUndecidableLeafFailsClosed: every structurally undecidable leaf is never "true", so a predicate carrying it never grants.
func InvUndecidableLeafFailsClosed(r *InvRng) bool {
	leaf := invPick(r, invUndecidables)("subject.role")
	verb := invPick(r, []string{"read", "write", "delete"})
	ctx := map[string]any{"action": map[string]any{"verb": verb, "resource": "/x"}, "subject": map[string]any{"role": "admin"}}
	if invTri(leaf, ctx) == triTrue {
		return false
	}
	return !evaluatePredicates([]any{map[string]any{"verb": verb, "resource": "/x", "where": []any{leaf}}}, ctx)
}

// InvUndecidableGroupsFailClosed: not / all_of / any_of over undecidable or empty children are never "true".
func InvUndecidableGroupsFailClosed(_ *InvRng) bool {
	ctx := map[string]any{"action": map[string]any{"verb": "read", "resource": "/x"}, "subject": map[string]any{"role": "admin"}}
	child := map[string]any{"field": "subject.role", "op": "lt", "value": 5.0}
	for _, c := range []any{map[string]any{"not": child}, map[string]any{"all_of": []any{}}, map[string]any{"any_of": []any{}},
		map[string]any{"all_of": []any{child}}, map[string]any{"any_of": []any{child}}} {
		if invTri(c, ctx) == triTrue {
			return false
		}
	}
	return true
}

// InvMemberOfCycleSafe: member_of over a cyclic adjacency terminates with a correct verdict and fails closed on an unreachable target.
func InvMemberOfCycleSafe(r *InvRng) bool {
	target := invPick(r, []string{"a", "b", "c", "z"})
	rel := map[string]any{"a": []any{"b"}, "b": []any{"a", "c"}}
	ctx := map[string]any{"action": map[string]any{"verb": "read", "resource": "/x"}, "subject": map[string]any{"g": "a"}, "env": map[string]any{"rel": rel}}
	got := invTri(map[string]any{"field": "subject.g", "op": "member_of", "value": target, "collection": "env.rel"}, ctx)
	if target == "z" {
		return got == triFalse
	}
	return got == triTrue
}

var invKnownCaveatTypes = map[string]bool{"expires": true, "not_before": true, "rate": true, "max_blast_radius": true, "reversibility_max": true,
	"delegation_depth": true, "budget_alloc": true, "max_spend": true, "intent_session": true}

// InvUnknownCaveatTypeDenies: an unknown caveat type is never satisfied, so a caveat set containing it is never ok.
func InvUnknownCaveatTypeDenies(r *InvRng) bool {
	t := invString(r, 1, 12)
	for invKnownCaveatTypes[t] {
		t = invString(r, 1, 12)
	}
	cav, ctx := map[string]any{"type": t}, map[string]any{"now": float64(r.Int(0, 10_000_000))}
	if caveatSatisfied(cav, ctx) {
		return false
	}
	ok, _ := EvaluateCaveats([]any{cav}, ctx)
	return !ok
}

var invMutations = []string{"tamper-caveat", "drop-leaf-caveat", "swap-holder", "break-parent", "bad-sig", "wrong-root-issuer", "suite-mismatch",
	"break-id", "append-forged-hop"}

// InvForgedChainRejected: a legal chain mutated by one of nine attacks never verifies.
func InvForgedChainRejected(r *InvRng) bool {
	chain, err := InvArbChain(r)
	if err != nil {
		return false
	}
	mutation := invPick(r, invMutations)
	pick := r.Int(0, 1_000_000)
	aux, err := InvariantKeyPairFromSeed(InvArbSeed32(r))
	if err != nil {
		return false
	}
	caps, root := invCaps(chain), chain.RootIssuer
	if !invVerifies(caps, root) {
		return false
	}
	n := len(caps)
	idx := pick % n
	clone := func() []any { return deepCopy(caps).([]any) }
	rejects := func(m []any) bool { return !invVerifies(m, root) }
	switch mutation {
	case "tamper-caveat":
		m := clone()
		c := m[idx].(map[string]any)
		c["caveats"] = append(c["caveats"].([]any), map[string]any{"type": "expires", "at": invNum(999)})
		return rejects(m)
	case "drop-leaf-caveat":
		m := clone()
		c := m[n-1].(map[string]any)
		cv := c["caveats"].([]any)
		if len(cv) == 0 {
			return true // inapplicable
		}
		c["caveats"] = cv[:len(cv)-1]
		return rejects(m)
	case "swap-holder":
		m := clone()
		m[idx].(map[string]any)["holder"] = aux.Pub
		return rejects(m)
	case "break-parent":
		if n < 2 {
			return true
		}
		m := clone()
		m[max(1, idx)].(map[string]any)["parent"] = invHash(map[string]any{"bogus": "x", "tag": "not-a-real-parent"})
		return rejects(m)
	case "bad-sig":
		m := clone()
		m[idx].(map[string]any)["sig"] = b64.EncodeToString(aux.Signer.Sign([]byte{1, 2, 3, 4}))
		return rejects(m)
	case "wrong-root-issuer":
		if aux.Pub == root {
			return true
		}
		return !invVerifies(caps, aux.Pub)
	case "suite-mismatch":
		m := clone()
		m[idx].(map[string]any)["alg"] = "ml-dsa-65" // suite fields are bound into the body digest
		return rejects(m)
	case "break-id":
		m := clone()
		m[idx].(map[string]any)["id"] = invHash(map[string]any{"not": "the-body-digest", "n": invNum(idx)})
		return rejects(m)
	}
	// append-forged-hop: issued as if from the leaf, but signed by a key that is not the leaf's holder
	forged, err := Delegate(chain.Caps[n-1], aux.Signer, aux.Pub, nil, "", nil)
	if err != nil {
		return true // refused outright
	}
	return rejects(append(clone(), forged))
}

// InvGarbageChainRejected: arbitrary never-signed chains (including the empty chain) never verify.
func InvGarbageChainRejected(r *InvRng) bool {
	chain := invToAny(invArray(r, func(r *InvRng) map[string]any {
		return map[string]any{"id": invString(r, 0, 10), "issuer": invString(r, 0, 10), "holder": invString(r, 0, 10),
			"caveats": []any{map[string]any{"type": invString(r, 0, 10)}}, "body_digest": invString(r, 0, 10), "sig": invString(r, 0, 10)}
	}, 0, 4))
	return !invVerifies(chain, "")
}

// InvDeterminism: VerifyChain, predicates, caveats, the risk score, the threshold and Admit are deterministic.
func InvDeterminism(r *InvRng) bool {
	chain, err := InvArbChain(r)
	if err != nil {
		return false
	}
	pt, preds := InvArbEvalPoint(r), InvArbPredicateList(r)
	policy, inputs, budget := InvArbRiskPolicy(r), InvArbRiskInputs(r), InvArbTrustBudget(r)
	caps := invCaps(chain)
	if invVerifies(caps, chain.RootIssuer) != invVerifies(caps, chain.RootIssuer) {
		return false
	}
	if evaluatePredicates(preds, pt.Action) != evaluatePredicates(preds, pt.Action) {
		return false
	}
	leaf := invCapCaveats(caps[len(caps)-1])
	c1, f1 := EvaluateCaveats(leaf, pt.CavCtx)
	c2, f2 := EvaluateCaveats(leaf, pt.CavCtx)
	if c1 != c2 || strings.Join(f1, "|") != strings.Join(f2, "|") {
		return false
	}
	s := RiskScore(inputs, policy.Weights)
	return s == RiskScore(inputs, policy.Weights) &&
		RequiredThresholdOf(s, policy.Theta1, policy.Theta2, false) == RequiredThresholdOf(s, policy.Theta1, policy.Theta2, false) &&
		Admit(s, budget, policy) == Admit(s, budget, policy)
}

// InvForbidMonotone: forbid-wins is monotone and order-independent: adding a forbid clause only moves a decision down, a matching
// forbid always denies, and the decision does not depend on clause order.
func InvForbidMonotone(r *InvRng) bool {
	ranks := map[string]int{"deny": 0, "escalate": 1, "allow": 2}
	mk := func(kind string, ps []any, tag string) []any {
		out := make([]any, len(ps))
		for i, w := range ps {
			out[i] = map[string]any{"id": fmt.Sprintf("%s%d", tag, i), "kind": kind, "when": w}
		}
		return out
	}
	permits, forbids, extra := InvArbPredicateList(r), InvArbPredicateList(r), InvArbPredicateList(r)
	pt, rot := InvArbEvalPoint(r), r.Int(0, 5)
	base := append(mk("permit", permits, "p"), mk("escalate", extra, "e")...)
	with := append(append([]any{}, base...), mk("forbid", forbids, "f")...)
	dec := func(c []any) string { s, _ := DecideClauses(c, pt.Action, nil, nil)["decision"].(string); return s }
	before, after := dec(base), dec(with)
	rb, okb := ranks[before]
	ra, oka := ranks[after]
	if !okb || !oka || ra > rb {
		return false
	}
	for _, w := range forbids {
		if WhenMatches(w, pt.Action) && after != "deny" {
			return false
		}
	}
	k := rot % len(with)
	return dec(append(append([]any{}, with[k:]...), with[:k]...)) == after
}

// InvariantCheck is one named invariant of the registry.
type InvariantCheck struct {
	Name string
	Prop InvProp
}

// InvariantRegistry lists the invariants in run order (the order of InvariantNames).
var InvariantRegistry = []InvariantCheck{
	{"attenuation-monotonicity", InvAttenuationMonotonicity},
	{"risk-wellformed-and-monotone", InvRiskMonotone},
	{"admission-soundness", InvAdmissionSoundness},
	{"cumulative-budget-bound", InvCumulativeBudgetBound},
	{"fail-closed:undecidable-leaf", InvUndecidableLeafFailsClosed},
	{"fail-closed:undecidable-groups", InvUndecidableGroupsFailClosed},
	{"fail-closed:member-of-cycle-safe", InvMemberOfCycleSafe},
	{"fail-closed:unknown-caveat-type", InvUnknownCaveatTypeDenies},
	{"fail-closed:forged-chain-rejected", InvForgedChainRejected},
	{"fail-closed:garbage-chain-rejected", InvGarbageChainRejected},
	{"forbid-monotone", InvForbidMonotone},
	{"determinism", InvDeterminism},
}

// InvariantResult is one invariant's outcome; OK false with Error is a surfaced counterexample (a candidate core bug).
type InvariantResult struct {
	Name    string
	OK      bool
	NumRuns int
	Seed    int64
	Error   string
}

func invRunProp(p InvProp, numRuns int, seed int64) (err error) {
	defer func() {
		if x := recover(); x != nil {
			err = fmt.Errorf("property panicked: %v", x)
		}
	}()
	master := NewInvRng(uint64(seed))
	for i := 0; i < numRuns; i++ {
		cs := master.U64()
		if !p(NewInvRng(cs)) {
			return fmt.Errorf("property failed after %d run(s) (seed %d, case seed %d)", i+1, seed, cs)
		}
	}
	return nil
}

// CheckInvariants machine-checks every invariant (bail stops at the first failure). numRuns <= 0 means InvariantsDefaultNumRuns; a
// count above 1e7 is refused. The seed is always explicit (pass InvariantsDefaultSeed for the default).
func CheckInvariants(numRuns int, seed int64, bail bool) ([]InvariantResult, error) {
	if numRuns == 0 {
		numRuns = InvariantsDefaultNumRuns
	}
	if numRuns < 1 || numRuns > 10_000_000 {
		return nil, errors.New("checkInvariants: numRuns must be a positive integer")
	}
	out := make([]InvariantResult, 0, len(InvariantRegistry))
	for _, inv := range InvariantRegistry {
		res := InvariantResult{Name: inv.Name, OK: true, NumRuns: numRuns, Seed: seed}
		if err := invRunProp(inv.Prop, numRuns, seed); err != nil {
			res.OK, res.Error = false, err.Error()
		}
		out = append(out, res)
		if bail && !res.OK {
			break
		}
	}
	return out, nil
}
